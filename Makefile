.PHONY: install test lint format typecheck all

install:
	uv sync

test:
	uv run pytest

lint:
	uv run ruff check src tests

format:
	uv run ruff format src tests

typecheck:
	uv run pyright src

all: lint typecheck test
