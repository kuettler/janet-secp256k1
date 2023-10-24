(declare-project
  :name "jsecp256k1"
  :description ```Binding to the secp256k1 functions.```
  )

(def cflags '[])
(def lflags '["-lsecp256k1"])

(declare-native
  :name "jsecp256k1"
  :source @["module.c"]
  :cflags [;default-cflags ;cflags]
  :lflags [;default-lflags ;lflags]
  )
