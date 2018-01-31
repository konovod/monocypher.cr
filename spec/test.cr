require "./spec_helper"
require "crypto/subtle"

salt1 = Crypto::Salt.new
salt2 = salt1
pp salt1, salt2, salt1.to_unsafe, salt2.to_unsafe, salt1.to_slice, salt2.to_slice
pp Crypto::Subtle.constant_time_compare(salt1.to_unsafe, salt2.to_unsafe)
pp Crypto::Subtle.constant_time_compare(salt1.to_slice, salt2.to_slice)
pp salt1.compare(salt2)
