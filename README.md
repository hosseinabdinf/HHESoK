# HHESoK
Implementation for Hybrid Homomorphic Encryption SoK

# Testing Instruction
To test each symmetric cipher, navigate to its respective directory:

    $ cd ./symcips/CNAME/

Then execute the following commands:

    $ go test

To obtain comprehensive benchmarking results, execute the following commands:

    $  go test -bench=^BenchmarkCNAME$ -benchmem

Replace "CNAME" with the name of the desired cipher, for which a benchmark is
available, from the following list:

    Available CNAMES for Benchmarking:
    - Pasta3:   PASTA cipher with 3 rounds
    - Pasta4:   PASTA cipher with 4 rounds
    - Hera:     HERA cipher
    - Rubato:   Rubato cipher
