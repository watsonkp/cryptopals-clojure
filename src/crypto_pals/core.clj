(ns crypto-pals.core
  (:require [clojure.data.codec.base64 :as b64]
            [clojure.math.numeric-tower :as math]
            [clojure.string :as str]
            [clojure.pprint :as pp]))

(defn base64-string-to-bytes [s]
  (let [convert (comp seq b64/decode byte-array (partial map byte))]
    (convert s)))

(defn base64-file-to-bytes [path]
  (let
    [clean (partial remove #(= \newline %))
     convert (comp seq b64/decode byte-array (partial map byte))]
    (convert (clean (slurp path)))))

(defn write-to-file
  [path content]
  (with-open [w (clojure.java.io/writer path)]
    (.write w content)))

; need to work on numbers not bytes
(defn hex-to-bytes
  [hex]
  (map #(+ (bit-shift-left (first %) 4) (second %))
       (partition 2
                  (map #(Integer/parseInt (String/valueOf %) 16) hex))))
;call these prints, and print
(defn bytes-to-hex
  [bytes]
    (apply str (map #(format "%02x" %) bytes)))

(defn bytes-to-base64
  [bytes]
  (apply str(map char (b64/encode (byte-array bytes)))))

(defn bytes-to-string
  [bytes]
  (apply str (map (comp char #(bit-and 0xff %)) bytes)))

(defn square-difference
  [x y]
  (reduce + (map second (merge-with #(math/expt (- %1 %2) 2) x y))))

(defn transpose [m] (apply mapv vector m))

(defn filter-whitespace
  [string]
  (apply str (filter #(not (clojure.string/blank? (str %))) string)))

(defn count-bits [n]
  (loop [c 0
         ;hack to make negatively signed bytes positive numbers
         v (bit-and n 0xff)]
    (if (zero? v)
      c
      (recur (inc c) (bit-and v (dec v))))))

(defn hamming-distance
  [x y]
  (reduce + (map (comp count-bits bit-xor)
                 x y)))

(defn random-bytes [n]
  (let [rng          (java.security.SecureRandom.)
        random-bytes (byte-array n)]
    (.nextBytes rng random-bytes)
    (seq random-bytes)))

;https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_the_English_language
(defn english-expected-frequencies
  []
  (let
    [regular {\a 0.08167 \b 0.01492 \c 0.02782 \d 0.04253
              \e 0.12702 \f 0.02228 \g 0.02015 \h 0.06094
              \i 0.06966 \j 0.00153 \k 0.00772 \l 0.04025
              \m 0.02406 \n 0.06749 \o 0.07507 \p 0.01929
              \q 0.00095 \r 0.05987 \s 0.06327 \t 0.09056
              \u 0.02758 \v 0.00978 \w 0.02360 \x 0.00150
              \y 0.01974 \z 0.00074}
     special {\* 0.0 \space 0.0 \. 0.0 \, 0.0}]
    (merge regular special)))

(defn build-frequency-table
  [string expected]
  (let [alpha (filter (set (map first expected))
                      (clojure.string/lower-case (clojure.string/replace string #"[^a-zA-Z .,]" "*")))]
    (into {} (for [[k v ] (frequencies alpha)]
               [k (/ v (count alpha))]))))

(defn frequency-test
  [in expected]
  (let [ranked (sort-by first
                        (for [c (range 0 256)]
                          (let [s (apply str (map (comp char #(bit-and 0xff %) #(bit-xor c %)) in))
                                score (square-difference (build-frequency-table s expected)
                                                         expected)]
                            (list score c s))))]
    ranked))

(defn repeating-key-xor
  [message key]
  (let
     [key-length (count key)
      message-subs (partition key-length key-length [] message)]
    (bytes-to-hex (mapcat #(map bit-xor % key) message-subs))))

(defn rank-key-sizes [message sizes]
  (sort-by second
           (for [size sizes]
             (let
               [block-pairs (partition 2 1 (partition size message))]
               (list size
                     (/ (reduce + (map #(/ (hamming-distance (first %)
                                                             (second %))
                                           size)
                                       block-pairs))
                        (count block-pairs)))))))

(defn break-key
  [message size]
  (let
    [transposed-message (transpose (partition size message))]
    (for [row transposed-message]
        (second (first (frequency-test row (english-expected-frequencies)))))))

(defn cbc? [cipher-text]
  (let [blocks          (partition 16 cipher-text)
        count-distinct  (comp count frequencies)
        duplicates      (- (count blocks) (count-distinct blocks))]
  (= 0 duplicates)))

; Note: if the message is an integer number of blocks then an extra block of 0x10
; will be added. This is necessary to make guarantees about validation add
; decoding.
(defn add-pkcs7-padding
  [message block-size]
  (let [last-block (take-last (mod (count message) block-size) message)
        padding-value (byte (- block-size (count last-block)))
        padding (repeat padding-value padding-value)]
      (concat message padding)))

(defn encrypt [cipher-key plain-text]
  (let [key-spec (javax.crypto.spec.SecretKeySpec. (byte-array cipher-key) "AES")
        cipher   (javax.crypto.Cipher/getInstance "AES/ECB/NoPadding")]
    (.init cipher javax.crypto.Cipher/ENCRYPT_MODE key-spec)
    (seq (.doFinal cipher (byte-array plain-text)))))

(defn decrypt
  [cipher-key cipher-text]
  (let
    [key-spec (javax.crypto.spec.SecretKeySpec. (byte-array cipher-key) "AES")
    cipher (javax.crypto.Cipher/getInstance "AES/ECB/NoPadding")]
    (.init cipher javax.crypto.Cipher/DECRYPT_MODE key-spec)
    (seq (.doFinal cipher (byte-array cipher-text)))))

(defn cbc-block [iv cipher plain-text]
  (let [encrypt-block (comp list cipher #(map bit-xor %1 %2))
        encrypt-all   (comp flatten #(drop 1 %) (partial reduce #(concat %1
                                                                         (encrypt-block (last %1) %2))))]
    (encrypt-all (list iv)
                 (partition (count iv) plain-text))))

(defn cbc-deblock [cipher-text plain-text iv]
  (let [block-size  (count iv)
        cipher-text (concat (list iv)
                            (partition block-size cipher-text))
        plain-text  (partition block-size plain-text)
        deblock     (comp flatten (partial map #(map bit-xor %1 %2)))]
    (deblock plain-text cipher-text)))

(defn encryption-oracle [plain-text]
  (let [block-size 16
        cipher-key (random-bytes block-size)
        rand-zero-pad (comp #(map byte %) #(repeat % 0))
        rand-5-10 #(+ 5 (rand-int 6))
        padded-message (add-pkcs7-padding (concat (rand-zero-pad (rand-5-10))
                                          plain-text
                                          (rand-zero-pad (rand-5-10)))
                                  block-size)]
    (if (= 0 (rand-int 2))
      ;use ECB
      (vector "ECB" (encrypt cipher-key padded-message))
      ;use CBC
      (let
        [iv (random-bytes block-size)
         cipher (partial cbc-block iv (partial encrypt cipher-key))]
        (vector "CBC" (cipher padded-message))))))

(defn aes-ecb-oracle [cipher-key plain-text prefix]
  (let [block-size (count cipher-key)]
    (encrypt cipher-key (add-pkcs7-padding (concat prefix plain-text)
                                         block-size))))

(defn measure-padding [block-size plain-text]
  (let [last-block (reverse (take-last block-size plain-text))
        b (first last-block)
        repeats (reduce #(if (= %2 b) (inc %1) (reduced %1)) 0 last-block)]
    (if (= b repeats) repeats 0)))

(defn get-block-size [oracle]
  (let [trials (map oracle (map #(repeat % (byte \A)) (drop 1 (range))))
        trial-lengths (map count trials)
        diffs (map - (drop 1 trial-lengths) trial-lengths)]
    (first (filter #(> % 0) diffs))))

; checks
; detect ecb
(defn break-ecb [oracle]
  (let [block-size (get-block-size oracle)
        prefix (map #(into [] (repeat % (byte \A))) (range (- block-size 1) -1 -1))
        blocks (map #(partition block-size %) (map oracle prefix))
        blocks (apply concat (apply (partial map vector) blocks))
        guess (fn [target prefix]
                (let [guesses (map #(identity [(let [p (conj (vec prefix) %)] (oracle p))
                                               %])
                                   (range 0xff))
                      guesses (map #(identity [(take block-size (first %))
                                               (second %)])
                                   guesses)
                      match (first (filter #(= target (first %))
                                           guesses))]
                (second match)))
        plain-text (reduce #(let [c (guess %2 (take-last (- block-size 1) %1))]
                                       (if c (conj %1 c) (reduced %1)))
                           (vec (repeat (- block-size 1) (byte \A)))
                           blocks)
        plain-text (drop (- block-size 1) plain-text)
        padding-length (measure-padding block-size plain-text)
        plain-text (drop-last padding-length plain-text)]
;        _ (println (apply str (map char plain-text)))]
    plain-text))

(defn kv-decode [s]
  (let [pairs (str/split s #"&")
        pairs (map #(str/split % #"=" 2) pairs)
        m (reduce #(assoc %1 (first %2) (second %2))
                  {}
                  pairs)]
    m))

(defn kv-encode [m]
  (let [pairs (map #(str/join "=" %) m)
        s (str/join "&" pairs)]
    s))

(defn profile-for [email]
  (let [email (apply str (filter #(and (not= \& %) (not= \= %)) (seq email)))
        m (merge {"email" email} {"uid" "10", "role" "user"})]
  (kv-encode m)))

(defn aes-ecb-oracle [cipher-key plain-text prefix]
  (let [block-size (count cipher-key)]
    (encrypt cipher-key (add-pkcs7-padding (concat prefix plain-text)
                                         block-size))))

(defn profile-oracle [cipher-key email]
  (let [block-size (count cipher-key)]
    (encrypt cipher-key (add-pkcs7-padding (map byte (profile-for email))
                                           block-size))))

(defn decryption-oracle [key message]
  (let [plain (decrypt key message)
        padding-length (measure-padding (count key) plain)]
    (drop-last padding-length plain)))

; This is uncomfortably specific to challenge 13.
(defn set-admin-profile [oracle]
  (let [block-size (get-block-size oracle)
        filler (repeat (- block-size (count "email=")) \A)
        admin-block (map char (add-pkcs7-padding (map byte "admin") block-size))
        admin-block (take block-size (drop block-size (oracle (concat filler admin-block))))
        email-length (- block-size (mod (count "email=&uid=10&role=") block-size))
        email (apply str (concat (repeat
                                   (- email-length (count "@bar.com"))
                                   \A)
                                 "@bar.com"))
        pure (oracle email)]
  (map byte (concat (drop-last block-size pure) admin-block))))

(defn prefixed-ecb-oracle [cipher-key prefix message suffix]
  (let [block-size (count cipher-key)]
;        _ (println (map byte (concat prefix message suffix)))]
    (encrypt cipher-key (add-pkcs7-padding (map byte (concat prefix message suffix))
                                           block-size))))

; todo check and guard against initial duplicate blocks
; todo return a byte count instead of a block count
(defn get-prefix-length [oracle]
  (let [block-size (get-block-size oracle)
        trials (map oracle (map #(repeat % \A) (drop 1 (range))))
        trials (map #(partition block-size %) trials)
        ; index 1 is comparing the second and third blocks
        ; get instead of indexOf
        mask (map #(.indexOf (map = (drop 1 %) %) true) trials)
        byte-index (reduce #(if (= %2 -1) (inc %1) (reduced %1)) 0 mask)
        byte-index (inc byte-index)
        block-index (first (filter #(> % -1) mask))]
    (+ (* (- (inc block-index) 2) block-size)
       (- block-size (mod byte-index block-size)))))

(defn break-prefixed-ecb [oracle]
  (let [block-size (get-block-size oracle)
        offset (get-prefix-length oracle)
        payload-padding (repeat (- block-size (mod offset 16)) (byte \A))
        offset-blocks (if (= (mod offset 16) 0) (quot offset block-size) (inc (quot offset block-size)))
        payload (map #(into [] (concat payload-padding
                                       (repeat % (byte \A))))
                     (range (- block-size 1) -1 -1))
        blocks (map #(drop offset-blocks (partition block-size %))
                    (map oracle payload))
        blocks (apply concat (apply (partial map vector) blocks))
        guess (fn [target prefix]
                (let [guesses (map #(identity [(let [p (conj (vec prefix) %)] (oracle p))
                                               %])
                                   (range 0x7f))
                      guesses (map #(identity [(take block-size (drop (* offset-blocks block-size) (first %)))
                                               (second %)])
                                   guesses)
                      match (first (filter #(= target (first %))
                                           guesses))]
                (second match)))
        plain-text (reduce #(let [c (guess %2 (concat payload-padding (take-last (- block-size 1) %1)))]
                                       (if c (conj %1 c) (reduced %1)))
                           (vec (repeat (- block-size 1) (byte \A)))
                           blocks)
        plain-text (drop (- block-size 1) plain-text)
        padding-length (measure-padding block-size plain-text)
        plain-text (drop-last padding-length plain-text)]
    plain-text))

(defn valid-padding? [message]
  (let [length (bit-and 0xff (last message))
        actual (reduce #(if (= length (bit-and 0xff %2)) (inc %1) (reduced %1))
                       0
                       (reverse message))]
    (= length actual)))

(defn remove-padding [message]
  (let [length (last message)]
    (if (valid-padding? message) (drop-last length message) nil)))

(defn aes [mode key message]
  (let [key-spec (javax.crypto.spec.SecretKeySpec. (byte-array key) "AES")
        cipher   (javax.crypto.Cipher/getInstance "AES/ECB/NoPadding")]
    (.init cipher mode key-spec)
    (seq (.doFinal cipher (byte-array message)))))

(defn aes-decrypt [key cipher-text]
  (aes javax.crypto.Cipher/DECRYPT_MODE key cipher-text))

(defn aes-encrypt [key plain-text]
  (aes javax.crypto.Cipher/ENCRYPT_MODE key plain-text))

(defn aes-cbc-decrypt [iv key cipher-text]
  (let [block-size (count iv)
        blocks (partition block-size cipher-text)]
    (flatten (map #(map bit-xor (aes-decrypt key %1) %2)
                  blocks
                  (concat (list iv) blocks)))))

(defn aes-cbc-encrypt [iv key plain-text]
  (let [block-size (count iv)
        blocks (partition block-size plain-text)]
    (drop block-size (reduce #(concat %1
                                      (aes-encrypt key (map bit-xor (take-last block-size %1) %2)))
                             iv
                             blocks))))

; todo quote out ; and =
(defn comment-oracle-encrypt [iv key userdata]
  (let [prefix "comment1=cooking%20MCs;userdata="
        suffix ";comment2=%20like%20a%20pound%20of%20bacon"
        message (concat prefix userdata suffix)
        message (add-pkcs7-padding (map byte message) 16)]
    (aes-cbc-encrypt iv key message)))

(defn comment-oracle-decrypt [iv key cipher-text]
  (let [plain-text (aes-cbc-decrypt iv key cipher-text)
        plain-text (apply str (map #(if (> % 0) (char %) (format "\\x%02x" (bit-and 0xff %))) plain-text))]
    plain-text))

(defn random-string-oracle [iv key]
  (let [s '("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="
             "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="
             "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="
             "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="
             "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"
             "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="
             "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="
             "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="
             "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="
             "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93")
        s (rand-nth s)
        s (base64-string-to-bytes s)
        block-size (count iv)]
    (aes-cbc-encrypt iv key (add-pkcs7-padding s 16))))

(defn padding-oracle [iv key cipher-text]
  (let [plain-text (aes-cbc-decrypt iv key cipher-text)]
;        _ (println (take-last 16 plain-text))]
    (valid-padding? plain-text)))

(defn attack-padding-oracle [oracle iv cipher-text]
  (let [uchar (partial bit-and 0xff)
        blocks (partition 16 (concat iv cipher-text))
        blocks (map-indexed #(into {} [[:prefix (flatten (take %1 blocks))]
                                       [:block %2]
                                       [:suffix (nth blocks (inc %1))]])
                            (drop-last 1 blocks))
        build-guesses (fn [prefix known suffix padding-byte]
                        (let [known (map #(bit-xor padding-byte %) known)]
                          (map #(into {} [[:cipher-text (concat prefix
                                                                (cons (bit-xor padding-byte %) '())
                                                                known
                                                                suffix)]
                                          [:guess %]])
                               (range 0x100))))
        decrypt-block (fn [block]
                        (reduce #(let [known (get %1 :decrypted)
                                       guesses (build-guesses (concat (get block :prefix)
                                                                      (take (- 15 (count known))
                                                                            (get block :block)))
                                                              known
                                                              (get block :suffix)
                                                              (inc (count known)))
                                       oracle (fn [g] (oracle (get g :cipher-text)))
                                       get-plain (fn [m] (bit-xor (get m :guess) (uchar %2)))
                                       matches (filter oracle guesses)
                                       match (get (apply max-key get-plain matches) :guess)
                                       plain (bit-xor (uchar %2) match)]
                                   (into {} [[:decrypted (cons match known)]
                                             [:plain (cons plain (get %1 :plain))]]))
                                '()
                                (reverse (get block :block))))
        out (map decrypt-block blocks)
        out (map #(get % :plain) out)
;        _ (println (apply str (map char (remove-padding (flatten out)))))
        ]
    (apply str (map char (remove-padding (flatten out))))))

(defn aes-ctr [key nonce message]
  (let [blocks (map #(concat nonce
                             (take 8 (concat (reverse (seq (.toByteArray (biginteger %))))
                                             (repeat 0))))
                    (range))
        key-stream (map #(aes-encrypt key %) blocks)
        plain-text (map (partial map bit-xor) (partition-all 16 message) key-stream)]
    (flatten plain-text)))

(defn attack-fixed-nonce-ctr [messages]
  (let [uchar (partial bit-and 0xff)
        messages (map #(into {} [[:message (vec (map uchar %))]
                                 [:length (count %)]])
                      messages)
        max-length (get (apply max-key #(get % :length) messages)
                        :length)
        get-nths (fn [xs i] (map #(get % i)
                                 (map #(get % :message) xs)))
        columns (map #(get-nths messages %) (range max-length))
        columns (reduce #(into %1 [[%2 (get-nths messages %2)]])
                        {}
                        (range max-length))
        f (map #(into [] [(first %)
                                   (first (apply max-key second (frequencies (remove nil? (second %)))))])
                        columns)
        ff (sort-by first f)
        max-freq (map second ff)

        ; \space being the most common character seems to work better than \e
;        guesses (vec (repeat (count max-freq) (byte \e)))
        guesses (vec (repeat (count max-freq) (byte \space)))

        ; Challenge 19 guess
;        guesses [65 104 32 32 32 111 111 101 101 104 32 32 32 32 101 32 32 32 32 116 32 101 32 32 115 32 111 32 101 104 105 100 32 116 117 114 110 101]

        ; Challenge 20 guess
        ; guesses [83 111 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 101 101 101 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 101 32 32 32 32 32 32 32 32 32 32 32 101 32 32 32 32 32 32 32 101 32 32 32 116 32 32 32 32 32 32 32 32 32 32 101 101 97 104 116 32 97 32 116 104 105 101 32 109 111 32 101 32 101 117 116 32 116 104 101 32 109 111 110 101 121 114 121]

        indices (take (count guesses) (cycle (range 10)))
        messages (map #(get % :message) messages)
        guess (fn [guesses line]
                (if (= (first line) \q)
                  guesses
                  (let [key-stream (map bit-xor max-freq guesses)
                        plain-texts (map #(map bit-xor key-stream %) messages)
                        readable (fn [c] (if (and (> c 0x19) (< c 0x7e))
                                           (char c)
                                           (format "\\x%02x" c)))
                        _ (prn indices)
                        _ (doseq [s plain-texts] (println (map readable s)))
                        _ (prn indices)
                        _ (prn guesses)
                        [matched-update col new-char] (re-matches #"([0-9]+) (.)" line)
                        guesses (if matched-update (assoc guesses
                                                          (Integer. col)
                                                          (byte (first new-char)))
                                  guesses)]
                    (recur guesses (read-line)))))
        guesses (guess guesses "")
        key-stream (map bit-xor max-freq guesses)
        plain-texts (map #(map bit-xor key-stream %) messages)
        plain-texts (map #(apply str (map char %)) plain-texts)
        _ (doseq [s plain-texts] (println s))
        ]
    plain-texts))

; Hopefully returns a lazy sequence of infinite length generated by the Mersenne
; Twister 19937 pseudo-random number generator using a 32 bit integer seed.
; Heavily based on the pseudocode at
; https://en.wikipedia.org/wiki/Mersenne_Twister#Pseudocode
(defn mt19937 [seed]
  (let [seed (bit-and 0xffffffff seed)
        w 32 n 624 m 397 r 31
        a 0x9908b0df
        u 11 d 0xffffffff
        s 7 b 0x9d2c5680
        t 15 c 0xefc60000
        l 18
        f 1812433253
        lower-32 (partial bit-and 0xffffffff)
        ; Set up the initial state
        init (fn [seed]
               (let [state (reduce #(conj %1
                                       (lower-32
                                                (+ (* f (bit-xor (last %1)
                                                                 (bit-shift-right (last %1)
                                                                                  (- w 2))))
                                                   %2)))
                                [seed]
                                (range 1 n))]
                 state))
        lower-mask (dec (bit-shift-left 1 r))
        upper-mask (lower-32 (bit-not lower-mask))
        ; Extract a random number from the state
        extract-number (fn [y]
                         (let [y (-> y (bit-shift-right u) (bit-and d) (bit-xor y))
                               y (-> y (bit-shift-left s) (bit-and b) (bit-xor y))
                               y (-> y (bit-shift-left t) (bit-and c) (bit-xor y))
                               y (-> y (bit-shift-right l) (bit-xor y))]
                           (lower-32 y)))
        ; Permute the internal state to produce the next n numbers
        twist (fn [mt]
                  (reduce #(let [xs (concat %1 (drop (count %1) mt))
                                 x (+ (bit-and upper-mask (nth xs %2))
                                      (bit-and lower-mask (nth xs (mod (inc %2) n))))
                                 xa (bit-shift-right x 1)
                                 xa (if (= (bit-and 1 x) 1)
                                      (bit-xor xa a)
                                      xa)
                                 mt-i (bit-xor (nth xs (mod (+ %2 m) n)) xa)]
                             (conj %1 mt-i))
                          []
                          (range n)))
        ; Start by twisting the initial state
        mt (twist (init seed))]
    ; Return the infinite sequence 
    (map extract-number (apply concat (iterate twist mt)))))

(defn brute-mt19937-time-seed [r0]
  (let [now (quot (System/currentTimeMillis) 1000)
        seed (filter #(= (first (mt19937 %))
                         r0)
                     (iterate dec now))]
    (first seed)))

(defn untemper-mt19937 [x]
  (let [nth-bits-block (fn [x n l]
                         ; breaks on zeroth block but that could be fixed with an if
                         (let [one-mask (->> n (* l) (bit-shift-left 1) (dec))
                               zero-mask (->> n (dec) (* l) (bit-shift-left 1) (dec))]
                           (bit-and x (- one-mask zero-mask))))
        un-shr-xor (fn [x l] (-> x (bit-shift-right l) (bit-xor x)))
        un-shl-xor (fn [x n c]
                     (let [y1 (->> n (bit-shift-left 1) (dec) (bit-and x))
                           y2 (->> y1
                                   (bit-shift-left n)
                                   (bit-and c)
                                   (bit-xor x)
                                   (bit-and (- (dec (bit-shift-left 1 (* 2 n)))
                                               (dec (bit-shift-left 1 n)))))
                           y3 (->> y2
                                   (bit-shift-left (* 2 n))
                                   (bit-and c)
                                   (bit-xor x)
                                   (bit-and (- (dec (bit-shift-left 1 (* 3 n)))
                                               (dec (bit-shift-left 1 (* 2 n))))))
                           ; the count can come from the length of %1
                           ; can the sequence it runs over be the split of x?
                           ys (reduce #(conj %1 (->> (first %1)
                                                     (bit-shiftleft (* %2 n))
                                                     (bit-and c)
                                                     (bit-xor x)
                                                     (nth-bits-block x %2 n)))
                                      '(y1)
                                      (range ))]
                       (apply + ys)))
        x (shr-xor x 18)
        x (shr-xor x 11)
        ]
    ))

(defn clone-mt19937 [xs]
  (let []
    ))
