CC=mpicc
CFLAGS=-O2 -I./src -std=c99 -D_POSIX_C_SOURCE=200809L
LDFLAGS=-lm -lrt

SRCS=src/main.c src/coordinator.c src/worker.c src/detectors.c src/block.c src/resource.c
TARGET=pdc

# helpers
PYTHON=python
PROCS=4
CSV=

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

.PHONY: ensure-dirs normalize run
ensure-dirs:
	@mkdir -p data output || true

# normalize a CSV into data/<name>_offline.csv using the script
normalize:
	if [ -z "$(CSV)" ]; then \
		echo "Usage: make normalize CSV=path/to/input.csv"; exit 1; \
	fi
	$(PYTHON) scripts/to_flows.py $(CSV)

# convenience run target: normalize then run with mpirun (CSV must be provided)
run: ensure-dirs $(TARGET)
	if [ -z "$(CSV)" ]; then \
		echo "Usage: make run CSV=data/<name>.csv PROCS=<n>"; exit 1; \
	fi
	$(PYTHON) scripts/to_flows.py $(CSV)
	mpirun -np $(PROCS) ./$(TARGET) data/$$(basename $(CSV) .csv)_offline.csv

clean:
	rm -f $(TARGET) output/*.txt output/*.csv output/*.log || true

