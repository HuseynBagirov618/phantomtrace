test:
	PYTHONPATH=src:. pytest

run:
	PYTHONPATH=src:. uvicorn apps.api.main:app --reload

demo:
	@echo "Demo command will be implemented later."

eval:
	@echo "Evaluation command will be implemented later."
