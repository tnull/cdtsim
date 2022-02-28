#!/bin/sh
PARALLEL_BIN=~/parallel

$PARALLEL_BIN -j 100 --bar "./target/release/cdtsim -r {1} -s {2} -a {3} -m {4}" ::: $(seq 1 30) ::: "mcentral" ::: 1000 10000 100000 1000000 10000000 100000000 ::: $(seq 1 30)
$PARALLEL_BIN -j 100 --bar "./target/release/cdtsim -r {1} -s {2} -a {3} -m {4}" ::: $(seq 1 30) ::: "lnbig" ::: 1000 10000 100000 1000000 10000000 100000000 ::: 1
$PARALLEL_BIN -j 100 --bar "./target/release/cdtsim -r {1} -s {2} -a {3} -m {4}" ::: $(seq 1 30) ::: "mrandom" ::: 1000 10000 100000 1000000 10000000 100000000 ::: $(seq 1 30)
