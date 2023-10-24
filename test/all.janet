(use jsecp256k1)

(defn to-hex [msg]
  (string/join (seq [ch :in msg] (string/format "%02x" ch))))

(def seckey "01234567890123456789012345678901")
(assert (ec-seckey-verify seckey))
(def public-key (ec-pubkey-create seckey))
(def public-key-serialized (ec-pubkey-serialize public-key))
(assert (= (to-hex public-key-serialized)
		   "02bb0debde80e350ba813b9836cb3b19fadc0d48ab2973f2a4323b5d45e1a44072"))
(assert (= (to-hex (ec-pubkey-serialize (ec-pubkey-parse public-key-serialized)))
		   "02bb0debde80e350ba813b9836cb3b19fadc0d48ab2973f2a4323b5d45e1a44072"))

(def seckey-2 (ec-seckey-tweak-add seckey seckey))
(assert (ec-seckey-verify seckey-2))
(def public-key-2 (ec-pubkey-create seckey-2))
(def public-key-serialized-2 (ec-pubkey-serialize public-key-2))
(assert (= (to-hex public-key-serialized-2)
		   "03f7e6274aa0cccaf03dfc52937cca2813c3451d91fe7ad078859fd91808d84545"))

# A crypotgraphic hash generated from a message
(def msghash32 "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
(def sig (ec-ecdsa-sign msghash32 seckey))

(assert (= (to-hex (ecdsa-signature-serialize-der sig))
		   "304402203a0258d939c7e6537b7af7e46d717336768f349b993d864c0342c3ff80e8168802205d1ffbfd68cb29db07754814e8bf0b7e07883987d9257a3a97118ea4eef251c5"))

(def sig-parsed (ecdsa-signature-parse-der (ecdsa-signature-serialize-der sig)))
(assert (ecdsa-verify sig-parsed msghash32 public-key))

(def sig-normalized (ecdsa-signature-normalize sig))
(assert sig-normalized)
(assert (= (to-hex (ecdsa-signature-serialize-der sig-normalized))
		   "304402203a0258d939c7e6537b7af7e46d717336768f349b993d864c0342c3ff80e8168802205d1ffbfd68cb29db07754814e8bf0b7e07883987d9257a3a97118ea4eef251c5"))
