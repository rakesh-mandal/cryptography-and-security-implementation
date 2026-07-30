#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>


void swap(int* a, int* b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

void copyArray(const int* src, int* dest, int size) {
    for (int i = 0; i < size; i++) {
        dest[i] = src[i];
    }
}

// Generates a random array of given size
void generateRandomArray(int* arr, int size) {
    for (int i = 0; i < size; i++) {
        arr[i] = rand() % 10000 + 1;
    }
}

// Helper to calculate execution time in microseconds using clock_t
double getTimeInMicroseconds(clock_t start, clock_t end) {
    return ((double)(end - start) / CLOCKS_PER_SEC) * 1e6;
}

// ==========================================
// 1. MERGE SORT
// ==========================================
void merge(int arr[], int left, int mid, int right) {
    int n1 = mid - left + 1;
    int n2 = right - mid;

    int L[n1], R[n2];
    for (int i = 0; i < n1; i++) L[i] = arr[left + i];
    for (int j = 0; j < n2; j++) R[j] = arr[mid + 1 + j];

    int i = 0, j = 0, k = left;
    while (i < n1 && j < n2) {
        if (L[i] <= R[j]) {
            arr[k++] = L[i++];
        } else {
            arr[k++] = R[j++];
        }
    }
    while (i < n1) arr[k++] = L[i++];
    while (j < n2) arr[k++] = R[j++];
}

void mergeSort(int arr[], int left, int right) {
    if (left < right) {
        int mid = left + (right - left) / 2;
        mergeSort(arr, left, mid);
        mergeSort(arr, mid + 1, right);
        merge(arr, left, mid, right);
    }
}
// ==========================================
// 2. QUICK SORT
// ==========================================
int partition(int arr[], int low, int high) {
    int pivot = arr[high];
    int i = low - 1;

    for (int j = low; j < high; j++) {
        if (arr[j] <= pivot) {
            i++;
            swap(&arr[i], &arr[j]);
        }
    }
    swap(&arr[i + 1], &arr[high]);
    return i + 1;
}

void quickSort(int arr[], int low, int high) {
    if (low < high) {
        int pi = partition(arr, low, high);
        quickSort(arr, low, pi - 1);
        quickSort(arr, pi + 1, high);
    }
}
// ==========================================
// 3. HEAP SORT
// ==========================================
void heapify(int arr[], int n, int i) {
    int largest = i;
    int left = 2 * i + 1;
    int right = 2 * i + 2;

    if (left < n && arr[left] > arr[largest])
        largest = left;

    if (right < n && arr[right] > arr[largest])
        largest = right;

    if (largest != i) {
        swap(&arr[i], &arr[largest]);
        heapify(arr, n, largest);
    }
}

void heapSort(int arr[], int n) {
    for (int i = n / 2 - 1; i >= 0; i--)
        heapify(arr, n, i);

    for (int i = n - 1; i > 0; i--) {
        swap(&arr[0], &arr[i]);
        heapify(arr, i, 0);
    }
}



// ==========================================
// MAIN
// ==========================================
int main() {
    int sizes[] = {100, 200, 300, 400, 500};
    int numSizes = sizeof(sizes) / sizeof(sizes[0]);
    const int RUNS = 1000; 

    
    double mergeAvgs[numSizes], quickAvgs[numSizes], heapAvgs[numSizes];
    double mergeCs[numSizes],   quickCs[numSizes],   heapCs[numSizes];

    
    srand(time(NULL));

    for (int s = 0; s < numSizes; s++) {
        int size = sizes[s];

        double totalMergeTime = 0.0;
        double totalHeapTime = 0.0;
        double totalQuickTime = 0.0;

        int* baseArray = (int*)malloc(size * sizeof(int));
        int* testArray = (int*)malloc(size * sizeof(int));

        clock_t start, end;

        for (int r = 0; r < RUNS; r++) {
            generateRandomArray(baseArray, size);

            // Merge Sort
            copyArray(baseArray, testArray, size);
            start = clock();
            mergeSort(testArray, 0, size - 1);
            end = clock();
            totalMergeTime += getTimeInMicroseconds(start, end);
            
            // Quick Sort
            copyArray(baseArray, testArray, size);
            start = clock();
            quickSort(testArray, 0, size - 1);
            end = clock();
            totalQuickTime += getTimeInMicroseconds(start, end);

            // Heap Sort
            copyArray(baseArray, testArray, size);
            start = clock();
            heapSort(testArray, size);
            end = clock();
            totalHeapTime += getTimeInMicroseconds(start, end);
        }

        free(baseArray);
        free(testArray);

        // Calculate averages
        mergeAvgs[s] = totalMergeTime / RUNS;
        quickAvgs[s] = totalQuickTime / RUNS;
        heapAvgs[s]  = totalHeapTime / RUNS;

        // Calculate constant factors C = Time / (N * log2(N))
        double x = size * log2((double)size);
        mergeCs[s] = mergeAvgs[s] / x;
        quickCs[s] = quickAvgs[s] / x;
        heapCs[s]  = heapAvgs[s] / x;
    }

    printf("Times are averaged over %d runs.\n\n", RUNS);

    
    printf("TABLE 1: AVERAGE EXECUTION TIME (microseconds)\n");
    printf("============================================================\n");
    printf("%-10s %-15s %-15s %-15s\n", "Size (N)", "Merge Sort", "Quick Sort", "Heap Sort");
    printf("============================================================\n");
    for (int s = 0; s < numSizes; s++) {
        printf("%-10d %-15.4f %-15.4f %-15.4f\n",
               sizes[s], mergeAvgs[s], quickAvgs[s], heapAvgs[s]);
    }
    printf("============================================================\n\n");

    
    printf("TABLE 2: CONSTANT FACTOR C = Time / (N * log2(N))\n");
    printf("============================================================\n");
    printf("%-10s %-15s %-15s %-15s\n", "Size (N)", "Merge C", "Quick C", "Heap C");
    printf("============================================================\n");
    for (int s = 0; s < numSizes; s++) {
        printf("%-10d %-15.8f %-15.8f %-15.8f\n",
               sizes[s], mergeCs[s], quickCs[s], heapCs[s]);
    }
    printf("============================================================\n");

    return 0;
}
