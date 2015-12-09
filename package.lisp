(defpackage #:cl-soda
  (:use #:cl #:cffi #:named-readtables #:optima)
  (:export
   #:make-signing-keypair
   #:crypto-sign #:crypto-sign-open #:make-box-keypair #:crypto-box-precompute
   #:crypto-box #:nonce-increment #:make-zero-nonce #:crypto-box-open))
