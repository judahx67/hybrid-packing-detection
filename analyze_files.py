import os
import subprocess
import glob
from pathlib import Path
import time
from datetime import datetime
from collections import defaultdict

def get_venv_python():
    venv_python = os.path.join(".venv", "Scripts", "python.exe")
    if os.path.exists(venv_python):
        return venv_python
    return "python"  # fallback to sPATH 

def log_debug(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")
# Get packer name 
def get_packer_name(file_path):
    path_parts = file_path.split(os.sep)
    if len(path_parts) > 2 and path_parts[0] == "packed":
        return path_parts[1] 
    return "not-packed"

def run_analysis(file_path):
    try:
        log_debug(f"Starting analysis of: {file_path}")
        start_time = time.time()
        
        venv_python = get_venv_python()
        # Run combined detector -> get output 
        process = subprocess.Popen([venv_python, 'combined_detector.py', file_path],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 text=True,
                                 bufsize=1,
                                 universal_newlines=True)
        
        # Read output and filter 
        output_lines = []
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                if any(x in output for x in ["[DETECTED]", "[FINAL VERDICT]", "[PACKED]", "[NOT PACKED]"]):
                    output_lines.append(output.strip())
        
        # Get any remaining output
        remaining_output, stderr = process.communicate()
        if remaining_output:
            # Filter remaining output
            for line in remaining_output.split('\n'):
                if any(x in line for x in ["[DETECTED]", "[FINAL VERDICT]", "[PACKED]", "[NOT PACKED]"]):
                    output_lines.append(line.strip())
        
        analysis_time = time.time() - start_time
        log_debug(f"Time taken: {analysis_time:.2f} seconds")
        
        if stderr:
            log_debug(f"Warning/Error output: {stderr}", "WARNING")
            
        return "\n".join(output_lines)
    except Exception as e:
        log_debug(f"Error analyzing {file_path}: {str(e)}", "ERROR")
        return f"Error analyzing {file_path}: {str(e)}"

def calculate_score(file_path, result):
    # packed ->has packer name. not-packed -> no packer name. 
    path_parts = file_path.split(os.sep)
    actual_packer = path_parts[1] if len(path_parts) > 2 and path_parts[0] == "packed" else "not-packed"
    
    # Check output
    is_detected_as_packed = "[PACKED]" in result
    
    # Scoring
    if actual_packer == "not-packed":
        if not is_detected_as_packed:
            score = 1  # True negative
            classification = "true_negatives"
            log_debug(f"True negative: {file_path} (not packed and detected as not packed)")
        else:
            score = -1  # False positive
            classification = "false_positives"
            log_debug(f"False positive: {file_path} (not packed but detected as packed)", "WARNING")
    else:  # File is packed
        if is_detected_as_packed:
            score = 1  # True positive
            classification = "true_positives"
            log_debug(f"True positive: {file_path} (packed and detected as packed)")
        else:
            score = -1  # False negative
            classification = "false_negatives"
            log_debug(f"False negative: {file_path} (packed but not detected)", "WARNING")
    
    return score, classification, actual_packer

def calculate_metrics(classifications, packer_stats):
    # Metricschesting 
    total = sum(classifications.values())
    accuracy = (classifications["true_positives"] + classifications["true_negatives"]) / total if total > 0 else 0
    
    true_positives = classifications["true_positives"]
    false_positives = classifications["false_positives"]
    false_negatives = classifications["false_negatives"]
    
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
        "classifications": classifications,
        "packer_stats": packer_stats
    }
# needs fixing 
def save_results(results, classifications, packer_stats, total_score, total_files, start_time):

    metrics = calculate_metrics(classifications, packer_stats)
    
    # Create concise results
    concise_results = []
    
    # Add packer statistics
    concise_results.append("\nPacker Detection Statistics:\n")
    for packer, stats in metrics['packer_stats'].items():
        if packer != "not-packed":
            concise_results.append(f"{packer}:")
            concise_results.append(f"  Total files: {stats['total']}")
            concise_results.append(f"  Correctly identified: {stats['correctly_identified']}")
            concise_results.append(f"  Detection rate: {(stats['correctly_identified'] / stats['total'] * 100):.0f}%\n")
    
    # Add overall 
    concise_results.append("Overall Performance:")
    concise_results.append(f"Accuracy: {metrics['accuracy']:.2%}")
    concise_results.append(f"Precision: {metrics['precision']:.2%}")
    concise_results.append(f"Recall: {metrics['recall']:.2%}")
    concise_results.append(f"F1 Score: {metrics['f1_score']:.2f}\n")
    
    # Add summary
    total_time = time.time() - start_time
    concise_results.append("Summary:")
    concise_results.append(f"Total files analyzed: {total_files}")
    concise_results.append(f"Total analysis time: {total_time:.2f} seconds")
    concise_results.append(f"Average time per file: {total_time/total_files:.2f} seconds")
    
    # Write results to file
    log_debug(f"Writing results to analysis_results.txt")
    with open("analysis_results.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(concise_results))
    
    log_debug("Results saved successfully")

def main():
    start_time = time.time()
    log_debug("Starting analysis process")

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
    
    packer_stats = defaultdict(lambda: {
        "total": 0,
        "correctly_identified": 0
    })
    
    try:
        # To alternate between packed and not-packed
        packed_patterns = glob.glob("packed/**/*.exe", recursive=True)
        not_packed_patterns = glob.glob("not-packed/*.exe")
        
        log_debug(f"Found {len(packed_patterns)} packed files and {len(not_packed_patterns)} not-packed files to analyze")
        
        # Process files alternately
        max_files = max(len(packed_patterns), len(not_packed_patterns))
        for i in range(max_files):
            if i < len(packed_patterns):
                file_path = packed_patterns[i]
                log_debug(f"Processing packed file {i+1}/{len(packed_patterns)}: {file_path}")
                result = run_analysis(file_path)
                score, classification, actual_packer = calculate_score(file_path, result)
                total_score += score
                total_files += 1
                classifications[classification] += 1
               
                packer_stats[actual_packer]["total"] += 1
                if classification == "true_positives":  # Correctly identified as packed
                    packer_stats[actual_packer]["correctly_identified"] += 1
            
         
            if i < len(not_packed_patterns):
                file_path = not_packed_patterns[i]
                log_debug(f"Processing not-packed file {i+1}/{len(not_packed_patterns)}: {file_path}")
                result = run_analysis(file_path)
                score, classification, actual_packer = calculate_score(file_path, result)
                total_score += score
                total_files += 1
                classifications[classification] += 1
                
                packer_stats[actual_packer]["total"] += 1
                if classification == "true_negatives":  # Correctly identified as not packed
                    packer_stats[actual_packer]["correctly_identified"] += 1
        
        # Save final results
        save_results(results, classifications, packer_stats, total_score, total_files, start_time)
        log_debug("Analysis process completed")
        
    except KeyboardInterrupt:
        log_debug("Analysis interrupted by user", "WARNING")
        if total_files > 0:
            save_results(results, classifications, packer_stats, total_score, total_files, start_time)
            log_debug(f"Saved partial results for {total_files} files")
        else:
            log_debug("No files were analyzed, nothing to save", "WARNING")
    except Exception as e:
        log_debug(f"Error during analysis: {str(e)}", "ERROR")
        if total_files > 0:
            save_results(results, classifications, packer_stats, total_score, total_files, start_time)
            log_debug(f"Saved partial results for {total_files} files")
        else:
            log_debug("No files were analyzed, nothing to save", "WARNING")

if __name__ == "__main__":
    main() 