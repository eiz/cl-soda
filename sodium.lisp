(in-package :cl-soda)
(in-readtable :fare-quasiquote)
#+5am (5am:in-suite* :cl-soda.tests)

(define-foreign-library libsodium
  (t (:default "libsodium")))

(defctype size :unsigned-int)

(defcfun ("sodium_init" %sodium-init) :void)
(defcfun ("sodium_version_string" %sodium-version-string) (:pointer :char))
(defcfun ("randombytes_random" %randombytes-random) :uint32)
(defcfun ("randombytes_stir" %randombytes-stir) :void)
(defcfun ("sodium_memzero" %sodium-memzero) :void 
  (ptr :pointer) (size size))
(defcfun ("sodium_memcmp" %sodium-memcmp) :int
  (p1 :pointer)
  (p2 :pointer)
  (size size))

;; crypto_auth
(defcfun ("crypto_auth_bytes" %crypto-auth-bytes) size)
(defcfun ("crypto_auth_keybytes" %crypto-auth-keybytes) size)
(defcfun ("crypto_auth_primitive" %crypto-auth-primitive) (:pointer :char))
(defcfun ("crypto_auth" %crypto-auth) :int
  (out :pointer)
  (in :pointer)
  (in-len :long-long)
  (k :pointer))
(defcfun ("crypto_auth_verify" %crypto-auth-verify) :int
  (h :pointer)
  (in :pointer)
  (in-len :long-long)
  (key :pointer))

;; crypto_box
(defcfun ("crypto_box_publickeybytes" %crypto-box-publickeybytes) size)
(defcfun ("crypto_box_secretkeybytes" %crypto-box-secretkeybytes) size)
(defcfun ("crypto_box_beforenmbytes" %crypto-box-beforenmbytes) size)
(defcfun ("crypto_box_noncebytes" %crypto-box-noncebytes) size)
(defcfun ("crypto_box_zerobytes" %crypto-box-zerobytes) size)
(defcfun ("crypto_box_boxzerobytes" %crypto-box-boxzerobytes) size)
(defcfun ("crypto_box_macbytes" %crypto-box-macbytes) size)
(defcfun ("crypto_box_primitive" %crypto-box-primitive) :pointer)
(defcfun ("crypto_box_keypair" %crypto-box-keypair) :int
  (public-key :pointer)
  (secret-key :pointer))
(defcfun ("crypto_box_beforenm" %crypto-box-beforenm) :int
  (k :pointer)
  (pk :pointer)
  (sk :pointer))
(defcfun ("crypto_box_afternm" %crypto-box-afternm) :int
  (c :pointer)
  (m :pointer)
  (mlen :unsigned-long-long)
  (n :pointer)
  (k :pointer))
(defcfun ("crypto_box" %crypto-box) :int
  (c :pointer)
  (m :pointer)
  (mlen :unsigned-long-long)
  (n :pointer)
  (pk :pointer)
  (sk :pointer))
(defcfun ("crypto_box_open" %crypto-box-open) :int
  (m :pointer)
  (c :pointer)
  (clen :unsigned-long-long)
  (n :pointer)
  (pk :pointer)
  (sk :pointer))
(defcfun ("crypto_box_open_afternm" %crypto-box-open-afternm) :int
  (m :pointer)
  (c :pointer)
  (clen :unsigned-long-long)
  (n :pointer)
  (k :pointer))

;; crypto_sign
(defcfun ("crypto_sign_bytes" %crypto-sign-bytes) size)
(defcfun ("crypto_sign_seedbytes" %crypto-sign-seedbytes) size)
(defcfun ("crypto_sign_publickeybytes" %crypto-sign-publickeybytes) size)
(defcfun ("crypto_sign_secretkeybytes" %crypto-sign-secretkeybytes) size)
(defcfun ("crypto_sign_primitive" %crypto-sign-primitive) :pointer)
(defcfun ("crypto_sign_seed_keypair" %crypto-sign-seed-keypair) :int
  (pk :pointer)
  (sk :pointer)
  (seed :pointer))
(defcfun ("crypto_sign_keypair" %crypto-sign-keypair) :int
  (pk :pointer) 
  (sk :pointer))
(defcfun ("crypto_sign" %crypto-sign) :int
  (sm :pointer)
  (smlen (:pointer :unsigned-long-long))
  (m :pointer)
  (mlen :unsigned-long-long)
  (sk :pointer))
(defcfun ("crypto_sign_open" %crypto-sign-open) :int
  (m :pointer)
  (mlen (:pointer :unsigned-long-long))
  (sm :pointer)
  (smlen :unsigned-long-long)
  (pk :pointer))


(defclass foreign-block ()
  ((pointer :initarg :pointer :reader foreign-block-pointer)
   (size :initarg :size :reader foreign-block-size)))

(defmethod dispose ((object foreign-block))
  (with-slots (pointer) object
    (when (and pointer (not (null-pointer-p pointer)))
      (let ((orig pointer))
        (setf pointer nil)
        (foreign-free orig)))))

(defclass keypair ()
  ((public-key :initform nil :initarg :public-key :reader keypair-public-key)
   (private-key :initform nil 
                :initarg :private-key 
                :reader keypair-private-key)))

(defmethod dispose ((key keypair))
  (with-slots (public-key private-key) key
    (dispose public-key)
    (dispose private-key)))

(defclass sign-keypair (keypair) ())
(defclass box-keypair (keypair) ())

(defun make-signing-keypair ()
  (let ((pk (foreign-alloc :char :count (%crypto-sign-publickeybytes)))
	(sk (foreign-alloc :char :count (%crypto-sign-secretkeybytes))))
    (%crypto-sign-keypair pk sk)
    (make-instance 'sign-keypair
		   :public-key (make-instance 
				'foreign-block
				:pointer pk
				:size (%crypto-sign-publickeybytes))
		   :private-key (make-instance
				 'foreign-block
				 :pointer sk
				 :size (%crypto-sign-secretkeybytes)))))

(defun has-private-key-p (keypair)
  (let ((sk (keypair-private-key keypair)))
    (and sk (not (null-pointer-p (foreign-block-pointer sk))))))

(defun has-public-key-p (keypair)
  (let ((pk (keypair-public-key keypair)))
    (and pk (not (null-pointer-p (foreign-block-pointer pk))))))

; I optimized this for no good reason.
(defun foreign-block-to-hex (fblock)
  (declare (optimize (speed 3) (safety 0) (compilation-speed 0)
		     (space 0) (debug 0)))
  (let* ((sz (foreign-block-size fblock))
	 (ptr (foreign-block-pointer fblock))
	 (str (make-string (* sz 2))))
    (check-type sz fixnum)
    (loop for i of-type fixnum from 0 below sz do
	 (let* ((val (the fixnum (mem-aref ptr :unsigned-char i)))
		(lo (the fixnum (logand val #x0F)))
		(hi (the fixnum (logand (the fixnum (ash val -4)) #xF))))
	   (setf (char str (the fixnum (* i 2)))
		 (if (> hi 9) 
		     (code-char (the fixnum (+ (the fixnum (char-code #\A)) 
					       (the fixnum (- hi 10)))))
		     (code-char (the fixnum (+ (char-code #\0) hi)))))
	   (setf (char str (the fixnum (1+ (the fixnum (* i 2)))))
		 (if (> lo 9)
		     (code-char (the fixnum (+ (the fixnum (char-code #\A)) 
					       (the fixnum (- lo 10)))))
		     (code-char (the fixnum (+ (the fixnum (char-code #\0)) 
					       lo)))))))
    str))

(defmacro with-bytes-as-foreign ((var array size 
				      &key (padding 0) (offset 0) length) 
				 &body body)
  (let ((array-var (gensym))
	(loop-var (gensym))
	(padding-var (gensym))
	(offset-var (gensym)))
    `(let ((,array-var ,array)
	   (,padding-var ,padding)
	   (,offset-var ,offset))
       (with-foreign-pointer (,var (+ ,padding-var 
				      (or ,length
                                          (- (length ,array-var)
                                             (or ,offset-var 0)))) ,size)
	 (when ,padding-var (%sodium-memzero ,var ,padding-var))
	 (loop for ,loop-var of-type fixnum from ,padding-var below ,size do
	      (setf (mem-aref ,var :unsigned-char ,loop-var)
		    (aref ,array-var (+ ,offset-var 
					(- ,loop-var ,padding-var)))))
	 ,@body))))

(defun bytes-from-foreign (ptr size &key (offset 0))
  (let* ((result-size (- size offset))
	 (result (make-array result-size :element-type '(unsigned-byte 8))))
    (loop for i from 0 below result-size do
	 (setf (aref result i) (mem-aref ptr :unsigned-char (+ i offset))))
    result))

(defun crypto-sign (bytes keypair)
  (check-type bytes (simple-array (unsigned-byte 8) *))
  (assert (has-private-key-p keypair))
  (with-bytes-as-foreign (f-bytes bytes size)
    (with-foreign-pointer (f-signed (+ size (%crypto-sign-bytes)) signed-size)
      (with-foreign-object (f-signed-length :unsigned-long-long)
	(%crypto-sign f-signed f-signed-length f-bytes size
		      (foreign-block-pointer (keypair-private-key keypair)))
	(let* ((result-length (mem-ref f-signed-length :unsigned-long-long))
	       (result (make-array result-length 
				   :element-type '(unsigned-byte 8))))
	  (loop for i of-type fixnum from 0 below result-length do
	       (setf (aref result i) (mem-aref f-signed :unsigned-char i)))
	  result)))))

(defun crypto-sign-open (bytes keypair)
  (check-type bytes (simple-array (unsigned-byte 8) *))
  (assert (has-public-key-p keypair))
  (with-bytes-as-foreign (f-signed bytes size)
    (with-foreign-pointer (f-message size)
      (with-foreign-object (f-message-length :unsigned-long-long)
	(if (eql -1 
		 (%crypto-sign-open f-message f-message-length f-signed size
				    (foreign-block-pointer 
				     (keypair-public-key keypair))))
	    nil
	    (let* ((result-length 
		    (mem-ref f-message-length :unsigned-long-long))
		   (result (make-array result-length
				       :element-type '(unsigned-byte 8))))
	      (loop for i of-type fixnum from 0 below result-length do
		   (setf (aref result i) (mem-aref f-message :unsigned-char i)))
	      result))))))

(defun make-box-keypair ()
  (let ((pk (foreign-alloc :char :count (%crypto-box-publickeybytes)))
	(sk (foreign-alloc :char :count (%crypto-box-secretkeybytes))))
    (%crypto-box-keypair pk sk)
    (make-instance 'box-keypair
		   :public-key (make-instance 
				'foreign-block
				:pointer pk
				:size (%crypto-box-publickeybytes))
		   :private-key (make-instance
				 'foreign-block
				 :pointer sk
				 :size (%crypto-box-secretkeybytes)))))

(defun crypto-box-precompute (public-keypair private-keypair)
  (let ((k (foreign-alloc :unsigned-char :count (%crypto-box-beforenmbytes))))
    (%crypto-box-beforenm k
			  (foreign-block-pointer 
			   (keypair-public-key public-keypair))
			  (foreign-block-pointer 
			   (keypair-private-key private-keypair)))
    (make-instance 'foreign-block
		   :pointer k
		   :size (%crypto-box-beforenmbytes))))

(defun crypto-box (bytes sender-keypair receiver-keypair nonce 
		   &optional precomputed)
  (unless precomputed
    (check-type sender-keypair box-keypair)
    (check-type receiver-keypair box-keypair)
    (assert (has-private-key-p sender-keypair))
    (assert (has-public-key-p receiver-keypair)))
  (when precomputed
    (assert (eql (%crypto-box-beforenmbytes) (foreign-block-size precomputed))))
  (check-type nonce (simple-array (unsigned-byte 8) *))
  (assert (eql (length nonce) (%crypto-box-noncebytes)))
  (with-bytes-as-foreign (f-bytes bytes size 
				  :padding (%crypto-box-zerobytes))
    (with-bytes-as-foreign (f-nonce nonce n-size)
      (with-foreign-pointer (f-box size)
	(if precomputed
	    (%crypto-box-afternm f-box f-bytes size f-nonce
				 (foreign-block-pointer precomputed))
	    (%crypto-box f-box f-bytes size f-nonce
			 (foreign-block-pointer 
			  (keypair-public-key receiver-keypair))
			 (foreign-block-pointer
			  (keypair-private-key sender-keypair))))
	(bytes-from-foreign f-box size 
			    :offset (%crypto-box-boxzerobytes))))))

(defun nonce-increment (nonce)
  (declare (optimize (speed 3) (safety 0) (compilation-speed 0) (debug 0))
	   (type (simple-array (unsigned-byte 8) *) nonce))
  (check-type nonce (simple-array (unsigned-byte 8) *))
  (let* ((last (the fixnum (1- (the fixnum (length nonce)))))
	 (next (1+ (the fixnum (aref nonce last))))
	 (carry (> next 255)))
    (declare (type fixnum next last)
	     (type boolean carry))
    (setf (aref nonce last) (the fixnum (logand next #xFF)))
    (loop for i of-type fixnum from (1- last) downto 0 while carry do
	 (setf next (1+ (the fixnum (aref nonce i)))
	       carry (> next 255)
	       (aref nonce i) (logand next #xFF))))
  nonce)

(defun make-zero-nonce ()
  (make-array (%crypto-box-noncebytes) :element-type '(unsigned-byte 8)))

(defun crypto-box-open (bytes sender-keypair receiver-keypair nonce
			&optional precomputed 
			&key 
			  (bytes-offset 0)
			  bytes-length)
  (unless precomputed
    (check-type sender-keypair box-keypair)
    (check-type receiver-keypair box-keypair)
    (assert (has-public-key-p sender-keypair))
    (assert (has-private-key-p receiver-keypair)))
  (when precomputed
    (assert (eql (%crypto-box-beforenmbytes) (foreign-block-size precomputed))))
  (check-type nonce (simple-array (unsigned-byte 8) *))
  (assert (eql (length nonce) (%crypto-box-noncebytes)))
  (with-bytes-as-foreign (f-bytes bytes size
				  :padding (%crypto-box-boxzerobytes)
				  :offset bytes-offset
				  :length bytes-length)
    (with-bytes-as-foreign (f-nonce nonce n-size)
     (with-foreign-pointer (f-message size)
       (let ((result
	      (if precomputed
		  (%crypto-box-open-afternm f-message f-bytes size f-nonce
					    (foreign-block-pointer precomputed))
		  (%crypto-box-open f-message f-bytes size f-nonce
				    (foreign-block-pointer
				     (keypair-public-key sender-keypair))
				    (foreign-block-pointer
				     (keypair-private-key receiver-keypair))))))
	 (when (eql 0 result)
	   (bytes-from-foreign f-message size 
			       :offset (%crypto-box-zerobytes))))))))

#+5am
(progn
  (5am:test crypto-box-simple
    (using ((sender (make-box-keypair))
            (receiver (make-box-keypair))
            (payload (ccl:encode-string-to-octets "Hello, World!"))
            (nonce (make-array 24 :element-type '(unsigned-byte 8)))
            (box (crypto-box payload sender receiver nonce))
            (result (crypto-box-open box sender receiver nonce)))
      (5am:is (not (null result)))
      (5am:is (equalp payload result))))
  (5am:test crypto-box-offset
    (using ((sender (make-box-keypair))
            (receiver (make-box-keypair))
            (payload (ccl:encode-string-to-octets "Hello, World!"))
            (nonce (make-array 24 :element-type '(unsigned-byte 8)))
            (box (crypto-box payload sender receiver nonce))
            (buffer (make-array (+ (length box) 16)
                                :element-type '(unsigned-byte 8))))
      (setf (subseq buffer 16) box)
      (let ((result (crypto-box-open buffer sender receiver nonce nil
                                     :bytes-offset 16)))
       (5am:is (not (null result)))
       (5am:is (equalp payload result)))))
  (5am:test crypto-box-wrong-offset
    (using ((sender (make-box-keypair))
            (receiver (make-box-keypair))
            (payload (ccl:encode-string-to-octets "Hello, World!"))
            (nonce (make-array 24 :element-type '(unsigned-byte 8)))
            (box (crypto-box payload sender receiver nonce))
            (buffer (make-array (+ (length box) 16)
                                :element-type '(unsigned-byte 8))))
      (setf (subseq buffer 16) box)
      (let ((result (crypto-box-open buffer sender receiver nonce nil
                                     :bytes-offset 15)))
       (5am:is (null result))))))

(defvar *sodium-initialized* nil)
(unless *sodium-initialized*
  (use-foreign-library libsodium)
  (%sodium-init)
  (setf *sodium-initialized* t))
