PY ?= python3
.PHONY: run worker test e2e demo docker
run:        ## start API + dashboard + inline worker on http://127.0.0.1:8000
	$(PY) -m autoforge.api.app
worker:     ## separate worker process (set INLINE_WORKER=0 for the API)
	$(PY) -m autoforge.worker
test:       ## unit, API, security and sandbox tests (deterministic mock provider, no network)
	$(PY) -W ignore -m unittest discover -s tests -t . -v
e2e:        ## browser journey (needs playwright + chromium)
	$(PY) tests/e2e_browser.py
demo:       ## run the full workflow against a running server and print evidence
	$(PY) infra/scripts/demo.py
docker:
	docker compose up --build
