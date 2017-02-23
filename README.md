# ciphermed-forests
Implementation of "Identifying Personal DNA Methylation Profiles by Genotype Inference" by Michael Backes, Pascal Berrang, Matthias Bieg, Roland Eils, Carl Herrmann, Mathias Humbert, Irina Lehmann

This code provides the means to privately evaluate a random forest classifier over the network.
Our implementation builds on "Machine Learning Classification over Encrypted Data" by Raphael Bost, Raluca Ada Popa, Stephen Tu and Shafi Goldwasser ([source code](https://github.com/rbost/ciphermed)).
 
It is available under the General Public License (GPL) version 3.
 
## Compilation & Prerequisites

As Ciphermed, Ciphermed-Forests builds on [JustGarble](http://cseweb.ucsd.edu/groups/justgarble/) which needs AES-NI enable on your CPU. Try `less /proc/cpuinfo | grep aes` to ensure these instructions are available. If not, you might have to disable all the garbled circuit-based code, or replace AES-NI calls by software AES.

Ciphermed-Forests directly uses GMP, HELib, boost, and others. You will need to install these and their own dependencies.

### [GMP](https://gmplib.org)

The C++ support of GMP is used in Ciphermed-Forests, so be sure to use the option `--enable-cxx` when calling the `configure` script.

### NTL

Note that when building NTL, be sure to make GMP the underlying large integer library by calling `./configure NTL_GMP_LIP=on`.
For better performances, you might also want to use [GF2X](https://gforge.inria.fr/projects/gf2x/) (downloadable [here](https://gforge.inria.fr/frs/download.php/file/30873/gf2x-1.1.tar.gz)). 
In this case, call `./configure NTL_GMP_LIP=on NTL_GF2X_LIB=on`.
You will also need to change HELib's makefile (see later).

### HELib

[HELib](https://github.com/shaih/HElib) is an experimental Level Homomorphic Encryption library by Shai Halevi and Victor Shoup that builds on NTL (and GMP). So be sure to have NTL installed.

We tested our code with HELib commit `3829cac`. Newer versions of that library might require modifying the code.

To be properly used in Ciphermed-Forests, HELib's makefile needs to be modified: be sure to add `-fPIC` to `CFLAGS`:

``CFLAGS = -g -O2 -fPIC -std=c++11``

If you decided to use gf2x in NTL, to pass checks, don't forget to add `-lfg2x` in `LDLIBS`. Test programs won't compile otherwise. 

### Other dependencies

Ciphermed-Forests uses the following external libraries:

* boost (for the sockets)
* msg_pack (needed by JustGarble)
* OpenSSL (idem)
* Google's protocol buffers and the protoc compiler (for serialization)
* JsonCpp (for ML models I/O)


On Ubuntu, these are available as apt packages and can be installed using the command
``sudo apt-get install libboost-system-dev libmsgpack-dev libssl-dev libprotoc-dev protobuf-compiler libjsoncpp-dev
``

