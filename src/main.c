#define _POSIX_C_SOURCE 200809L
#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>

void coordinator_process(int world_size, const char *csv_path);
void worker_process(int rank);

int main(int argc, char **argv) {
    MPI_Init(&argc, &argv);
    int rank, size; MPI_Comm_rank(MPI_COMM_WORLD, &rank); MPI_Comm_size(MPI_COMM_WORLD, &size);

    if (argc < 2) {
        if (rank == 0) fprintf(stderr, "Usage: mpirun -np <procs> ./pdc data/<name>_offline.csv\n");
        MPI_Finalize();
        return 1;
    }
    const char *csv = argv[1];
    if (rank == 0) coordinator_process(size, csv);
    else worker_process(rank);
    MPI_Finalize();
    return 0;
}
