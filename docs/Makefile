DOX = "doxygen"
TEX = "pdflatex"
DOC_CONFIG = "doxyconfig"

all:
	$(DOX) $(DOC_CONFIG)
overview:
	$(TEX) overview.tex
fsm:
	$(TEX) fsm.tex

.PHONY: clean

clean:
	rm -f *.aux *.log *.pdf
