# Render the user manual: make -C docs/manual  (needs TeX Live and latexmk)
# The title page shows the l4h version: L4H_VERSION when set, as in release
# builds, otherwise what tools/version.sh derives from Git.
VERSION := $(shell ../../tools/version.sh)

l4h-manual.pdf: l4h-manual.tex version.tex
	latexmk -pdf -interaction=nonstopmode -halt-on-error l4h-manual.tex

# Rewritten only when the version changes, so latexmk reruns only then.
version.tex: FORCE
	@v='\newcommand{\lfourhversion}{\detokenize{$(VERSION)}}'; \
	[ "$$(cat $@ 2>/dev/null)" = "$$v" ] || printf '%s\n' "$$v" > $@

clean:
	latexmk -C l4h-manual.tex
	rm -f version.tex

.PHONY: clean FORCE
