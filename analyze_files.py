import os
import subprocess
import glob
from pathlib import Path
import time
from datetime import datetime

def get_venv_python():
    venv_python = os.path.join(".venv", "Scripts", "python.exe")
    if os.path.exists(venv_python):
        return venv_python
    return "python"  # fallback to system python if venv not found

def log_debug(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

def run_analysis(file_path):
    try:
        log_debug(f"Starting analysis of: {file_path}")
        start_time = time.time()
        
        venv_python = get_venv_python()
        log_debug(f"Using Python interpreter: {venv_python}")
        
        # Run the analysis and print output in real-time
        process = subprocess.Popen([venv_python, 'combined_detector.py', file_path],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 text=True,
                                 bufsize=1,
                                 universal_newlines=True)
        
        # Read and print output in real-time
        output_lines = []
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())  # Print in real-time
                output_lines.append(output.strip())
        
        # Get any remaining output
        remaining_output, stderr = process.communicate()
        if remaining_output:
            print(remaining_output.strip())
            output_lines.append(remaining_output.strip())
        
        analysis_time = time.time() - start_time
        log_debug(f"Analysis completed in {analysis_time:.2f} seconds")
        
        if stderr:
            log_debug(f"Warning/Error output: {stderr}", "WARNING")
            
        return "\n".join(output_lines)
    except Exception as e:
        log_debug(f"Error analyzing {file_path}: {str(e)}", "ERROR")
        return f"Error analyzing {file_path}: {str(e)}"

def calculate_score(file_path, result):
    # Check if file is in packed or not-packed directory
    path_parts = file_path.split(os.sep)
    is_packed = "not-packed" not in path_parts
    
    # Check if result indicates packing
    is_detected_as_packed = "[PACKED]" in result
    
    # Calculate score and determine classification
    if is_packed and is_detected_as_packed:
        score = 1  # True positive
        classification = "true_positives"
        log_debug(f"True positive: {file_path} (packed and detected as packed)")
    elif not is_packed and not is_detected_as_packed:
        score = 1  # True negative
        classification = "true_negatives"
        log_debug(f"True negative: {file_path} (not packed and detected as not packed)")
    elif is_packed and not is_detected_as_packed:
        score = -1  # False negative
        classification = "false_negatives"
        log_debug(f"False negative: {file_path} (packed but not detected)", "WARNING")
    else:  # not is_packed and is_detected_as_packed
        score = -1  # False positive
        classification = "false_positives"
        log_debug(f"False positive: {file_path} (not packed but detected as packed)", "WARNING")
    
    return score, classification

def calculate_metrics(true_positives, false_positives, true_negatives, false_negatives):
    # Calculate basic metrics
    total = true_positives + false_positives + true_negatives + false_negatives
    accuracy = (true_positives + true_negatives) / total if total > 0 else 0
    
    # Calculate precision (true positives / (true positives + false positives))
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    
    # Calculate recall (true positives / (true positives + false negatives))
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    
    # Calculate F1 score (harmonic mean of precision and recall)
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "true_negatives": true_negatives,
        "false_negatives": false_negatives
    }

def save_results(results, classifications, total_score, total_files, start_time):
    # Calculate metrics
    metrics = calculate_metrics(
        classifications["true_positives"],
        classifications["false_positives"],
        classifications["true_negatives"],
        classifications["false_negatives"]
    )
    
    # Add summary
    total_time = time.time() - start_time
    results.append(f"\nDetailed Metrics:")
    results.append(f"True Positives: {metrics['true_positives']}")
    results.append(f"False Positives: {metrics['false_positives']}")
    results.append(f"True Negatives: {metrics['true_negatives']}")
    results.append(f"False Negatives: {metrics['false_negatives']}")
    results.append(f"\nPerformance Metrics:")
    results.append(f"Accuracy: {metrics['accuracy']:.2%}")
    results.append(f"Precision: {metrics['precision']:.2%}")
    results.append(f"Recall: {metrics['recall']:.2%}")
    results.append(f"F1 Score: {metrics['f1_score']:.2%}")
    results.append(f"\nSummary:")
    results.append(f"Total files analyzed: {total_files}")
    results.append(f"Total score: {total_score}")
    results.append(f"Average score: {total_score/total_files:.2f}")
    results.append(f"Total analysis time: {total_time:.2f} seconds")
    results.append(f"Average time per file: {total_time/total_files:.2f} seconds")
    
    # Write results to file
    log_debug(f"Writing results to analysis_results.txt")
    with open("analysis_results.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(results))
    
    log_debug("Results saved successfully")

def main():
    start_time = time.time()
    log_debug("Starting analysis process")
    
    # Initialize counters
    total_score = 0
    total_files = 0
    results = []
    
    # Initialize classification counters
    classifications = {
        "true_positives": 0,
        "false_positives": 0,
        "true_negatives": 0,
        "false_negatives": 0
    }
    
    try:
        # Get all files to analyze
        packed_patterns = glob.glob("packed/**/*.exe", recursive=True)
        not_packed_patterns = glob.glob("not-packed/*.exe")
        
        log_debug(f"Found {len(packed_patterns)} packed files and {len(not_packed_patterns)} not-packed files to analyze")
        
        # Process files alternately
        max_files = max(len(packed_patterns), len(not_packed_patterns))
        for i in range(max_files):
            # Process packed file if available
            if i < len(packed_patterns):
                file_path = packed_patterns[i]
                log_debug(f"Processing packed file {i+1}/{len(packed_patterns)}: {file_path}")
                result = run_analysis(file_path)
                score, classification = calculate_score(file_path, result)
                total_score += score
                total_files += 1
                classifications[classification] += 1
                results.append(f"File: {file_path}")
                results.append(f"Result: {result}")
                results.append(f"Score: {score}")
                results.append(f"Classification: {classification}")
                results.append("-" * 80)
            
            # Process not-packed file if available
            if i < len(not_packed_patterns):
                file_path = not_packed_patterns[i]
                log_debug(f"Processing not-packed file {i+1}/{len(not_packed_patterns)}: {file_path}")
                result = run_analysis(file_path)
                score, classification = calculate_score(file_path, result)
                total_score += score
                total_files += 1
                classifications[classification] += 1
                results.append(f"File: {file_path}")
                results.append(f"Result: {result}")
                results.append(f"Score: {score}")
                results.append(f"Classification: {classification}")
                results.append("-" * 80)
        
        # Save final results
        save_results(results, classifications, total_score, total_files, start_time)
        log_debug("Analysis process completed")
        
    except KeyboardInterrupt:
        log_debug("Analysis interrupted by user", "WARNING")
        if total_files > 0:
            save_results(results, classifications, total_score, total_files, start_time)
            log_debug(f"Saved partial results for {total_files} files")
        else:
            log_debug("No files were analyzed, nothing to save", "WARNING")
    except Exception as e:
        log_debug(f"Error during analysis: {str(e)}", "ERROR")
        if total_files > 0:
            save_results(results, classifications, total_score, total_files, start_time)
            log_debug(f"Saved partial results for {total_files} files")
        else:
            log_debug("No files were analyzed, nothing to save", "WARNING")

if __name__ == "__main__":
    main() 