# CDTSIM

This repository contains an event-discrete simulation framework written in [Rust](https://rust-lang.org/) that allows to evaluate timing attacks on privacy in the Bitcoin Lightning Network.

## Build

	cargo build --release

## Usage

	USAGE:
		cdtsim [OPTIONS]

	FLAGS:
		-h, --help       Prints help information
		-V, --version    Prints version information

	OPTIONS:
		-s, --adversary <mcentral/mrandom/lnbig>    Sets the adversarial scenario.
		-a, --amount <MSAT>                         Determines the amount (in milli-satoshi) for each simulated payment.
		-m, --num_malicious <NUM>                   Sets the number of malicious nodes.
		-t, --num_tries <NUM>                       Sets the number of payment attempts that are tried in each simulation.
		-r, --run <NUM>                             Sets the run number / seed value for the simulation.


## Paper

Rohrer, Elias, and Florian Tschorsch. "Counting down thunder: Timing attacks on privacy in payment channel networks." Proceedings of the 2nd ACM Conference on Advances in Financial Technologies. 2020. 

[PDF](https://arxiv.org/pdf/2006.12143.pdf)

## BibTeX

	@inproceedings{rohrer20cdt,
	  author    = {Elias Rohrer and Florian Tschorsch},
	  title     = {Counting Down Thunder: Timing Attacks on Privacy in Payment Channel Networks},
	  booktitle = {{AFT} '20: 2nd {ACM} Conference on Advances in Financial Technologies, New York, NY, USA, October 21-23, 2020},
	  pages     = {214--227},
	  publisher = {{ACM}},
	  year      = {2020},
	  url       = {https://doi.org/10.1145/3419614.3423262},
	  doi       = {10.1145/3419614.3423262},
	}
