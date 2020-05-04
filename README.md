# HMAC-SHA1
Computes HMAC with SHA1 as Hash function

This code is an implementation of HMAC-SHA1 in pure python.<br>
This code only works with the given class, as it(class SHA1) takes ascii input and produce hexdigest.<br>
Hence, HMAC class is written in order to coordinate with its own SHA1 class.

Class SHA1 is a pure python implementation of SHA1 algorithm, the operations are done completely in binary format which makes the algorithm considerably slow. This approach I went is to achieve the very fundamental view of what's happening inside SHA1 algorithm.

This implementation of SHA1 is not recommended for large data.<br>
This is just for educational purpose to understand every step of algorithm.
