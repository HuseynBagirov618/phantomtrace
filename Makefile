test:
	pytest

run:
	uvicorn apps.api.main:app --reload

demo:
	@echo "Demo command will be implemented later."

eval:
	@echo "Evaluation command will be implemented later."