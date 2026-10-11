SLANGC ?= slangc

.PHONY: test bench
test:
	SLANGC="$(SLANGC)" ./tests/run.sh

bench:
	SLANGC="$(SLANGC)" sh ./bench/run.sh
