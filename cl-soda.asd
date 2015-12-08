(asdf:defsystem #:cl-soda
  :serial t
  :description "Minimal interface to libsodium"
  :author "Mackenzie Straight"
  :license "MIT"
  :depends-on (#:cffi #:fare-quasiquote-extras)
  :components ((:file "package")
               (:file "sodium")))
