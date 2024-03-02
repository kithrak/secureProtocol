import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Path to your client executable. Example: "./client" or "C:\\path\\to\\client.exe"
CLIENT_EXECUTABLE_PATH = "./client"

def run_client_and_measure_time():
    start_time = time.time()  # Start timing
    # Run the client executable
    result = subprocess.run([CLIENT_EXECUTABLE_PATH], capture_output=True, text=True)
    end_time = time.time()  # End timing
    
    if result.returncode == 0:
        return f"Client executed successfully, time taken: {end_time - start_time} seconds"
    else:
        return f"Client execution failed, return code: {result.returncode}. Error: {result.stderr}"

def main():
    num_clients = 500  # Number of parallel clients
    with ThreadPoolExecutor(max_workers=num_clients) as executor:
        # Submit all client executions to the executor
        futures = [executor.submit(run_client_and_measure_time) for _ in range(num_clients)]
        
        # Process completed futures as they complete
        for future in as_completed(futures):
            print(future.result())
        # Optionally, measure total time taken for all clients to run
        # Note: This includes overhead from thread management and may not reflect server processing time accurately

if __name__ == "__main__":
    main()