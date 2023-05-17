#include <stdio.h>
#include <stdlib.h>

void multiplyMatrices(double* A, double* B, double* C, int size) {
    for (int i = 0; i < size; i++) {
        for (int j = 0; j < size; j++) {
            double sum = 0.0;
            for (int k = 0; k < size; k++) {
                sum += A[i * size + k] * B[k * size + j];
            }
            C[i * size + j] = sum;
        }
    }
}

void readMatrixFromFile(const char* filename, double* matrix, int size) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        exit(1);
    }

    fread(matrix, sizeof(double), size * size, file);
    fclose(file);
}

void writeMatrixToFile(const char* filename, double* matrix, int size) {
    FILE* file = fopen(filename, "wb");
    if (file == NULL) {
        perror("Error opening file");
        exit(1);
    }

    fwrite(matrix, sizeof(double), size * size, file);
    fclose(file);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Please provide the size of the matrices as a command-line argument.\n");
        return 1;
    }

    int size = 128;

    // Allocate memory for matrices A, B, and C
    double* A = malloc(sizeof(double) * size * size);
    double* B = malloc(sizeof(double) * size * size);
    double* C = malloc(sizeof(double) * size * size);

    // Read matrices A and B from files
    readMatrixFromFile("input_0.txt", A, size);
    readMatrixFromFile("input_1.txt", B, size);

    // Multiply matrices A and B 1000 times
    for (int i = 0; i < 1000; i++) {
        multiplyMatrices(A, B, C, size);
    }

    // Write matrix C to file
    writeMatrixToFile("output.txt", C, size);

    // Free allocated memory
    free(A);
    free(B);
    free(C);

    return 0;
}
