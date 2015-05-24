DOX = "doxygen"
TEX = "pdflatex"
DOC_CONFIG = "doxyconfig"

all:
	$(DOX) $(DOC_CONFIG)
fsm:
	$(TEX) fsm.tex

.PHONY: clean

clean:
	for f in docs; do  \
    rm -f $f.aux $f.log $f.pdf;
	done
