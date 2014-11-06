(ns crypto-pals.core
  (:require [clojure.data.codec.base64 :as b64]
            [clojure.math.numeric-tower :as math]))

; need to work on numbers not bytes
(defn hex-to-bytes
  [hex]
  (map #(+ (bit-shift-left (first %) 4) (second %))
       (partition 2
                  (map #(Integer/parseInt (String/valueOf %) 16) hex))))
;call these prints, and print
(defn bytes-to-hex
  [bytes]
    (apply str (map #(format "%x" %) bytes)))

(defn bytes-to-base64
  [bytes]
  (apply str(map char (b64/encode (byte-array bytes)))))

(defn print-as-string
  [bytes]
  (println (apply str (map char bytes))))

(defn square-difference
  [x y]
  (reduce + (map second (merge-with #(math/expt (- %1 %2) 2) x y))))

;https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_the_English_language
(def character-frequency-table {\a 0.08167 \b 0.01492 \c 0.02782 \d 0.04253
                                \e 0.12702 \f 0.02228 \g 0.02015 \h 0.06094
                                \i 0.06966 \j 0.00153 \k 0.00772 \l 0.04025
                                \m 0.02406 \n 0.06749 \o 0.07507 \p 0.01929
                                \q 0.00095 \r 0.05987 \s 0.06327 \t 0.09056
                                \u 0.02758 \v 0.00978 \w 0.02360 \x 0.00150
                                \y 0.01974 \z 0.00074})
(defn build-frequency-table
  [string]
  (let [alpha (filter (set (map first character-frequency-table))
                      (clojure.string/lower-case string))]
    (into {} (for [[k v ] (frequencies alpha)]
               [k (/ v (count alpha))]))))

(defn frequency-test
  [in table]
  (let [ranked (sort-by first
                        (for [c (range 65 123)]
                          (let [s (apply str (map (comp char #(bit-xor (int c) %)) in))
                                score (square-difference (build-frequency-table s) character-frequency-table)]
                            (list score (char c) s))))
        winner (first ranked)
        _ (println (format "Byte %c scored %.3f and produced '%s'." (second winner) (first winner) (last winner)))]
    (last (first ranked))))
