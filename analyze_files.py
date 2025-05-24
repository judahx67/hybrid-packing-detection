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
    return "python"  # fallback to system python if venv not found

def log_debug(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

def get_packer_name(file_path):
    # Extract packer name from path
    path_parts = file_path.split(os.sep)
    if len(path_parts) > 2 and path_parts[0] == "packed":
        return path_parts[1]  # Return the packer name from subfolder
    return "not-packed"

def run_analysis(file_path):
    try:
        log_debug(f"Starting analysis of: {file_path}")
        start_time = time.time()
        
        venv_python = get_venv_python()
        
        # Run the analysis and capture output
        process = subprocess.Popen([venv_python, 'combined_detector.py', file_path],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 text=True,
                                 bufsize=1,
                                 universal_newlines=True)
        
        # Read output and filter for relevant messages
        output_lines = []
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                # Only keep relevant messages
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
        log_debug(f"Analysis completed in {analysis_time:.2f} seconds")
        
        if stderr:
            log_debug(f"Warning/Error output: {stderr}", "WARNING")
            
        return "\n".join(output_lines)
    except Exception as e:
        log_debug(f"Error analyzing {file_path}: {str(e)}", "ERROR")
        return f"Error analyzing {file_path}: {str(e)}"

def calculate_score(file_path, result):
    # Get actual packer used
    actual_packer = get_packer_name(file_path)
    
    # Check if result indicates packing
    is_detected_as_packed = "[PACKED]" in result
    
    # Extract detected packer name if available
    detected_packer = None
    for line in result.split('\n'):
        if "[DETECTED] Detected packer:" in line:
            detected_packer = line.split(":")[1].strip()
            break
    
    # Calculate score and determine classification
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
            if detected_packer and detected_packer.lower() == actual_packer.lower():
                score = 2  # True positive with correct packer identification
                classification = "true_positives_correct_packer"
                log_debug(f"True positive with correct packer: {file_path} (detected as {detected_packer})")
            else:
                score = 1  # True positive but wrong packer
                classification = "true_positives_wrong_packer"
                log_debug(f"True positive but wrong packer: {file_path} (actual: {actual_packer}, detected: {detected_packer})")
        else:
            score = -1  # False negative
            classification = "false_negatives"
            log_debug(f"False negative: {file_path} (packed with {actual_packer} but not detected)", "WARNING")
    
    return score, classification, actual_packer, detected_packer

def calculate_metrics(classifications, packer_stats):
    # Calculate overall metrics
    total = sum(classifications.values())
    accuracy = (classifications["true_positives_correct_packer"] + 
                classifications["true_positives_wrong_packer"] + 
                classifications["true_negatives"]) / total if total > 0 else 0
    
    true_positives = classifications["true_positives_correct_packer"] + classifications["true_positives_wrong_packer"]
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

def save_results(results, classifications, packer_stats, total_score, total_files, start_time):
    # Calculate metrics
    metrics = calculate_metrics(classifications, packer_stats)
    
    # Create concise results
    concise_results = []
    
    # Add packer statistics
    concise_results.append("\nPacker Detection Statistics:")
    for packer, stats in metrics['packer_stats'].items():
        if packer != "not-packed":
            concise_results.append(f"\n{packer}:")
            concise_results.append(f"  Total files: {stats['total']}")
            concise_results.append(f"  Correctly identified: {stats['correctly_identified']}")
            concise_results.append(f"  Detection rate: {(stats['correctly_identified'] / stats['total'] * 100):.2f}%")
            if stats['wrong_identifications']:
                concise_results.append(f"  Wrongly identified as: {', '.join(stats['wrong_identifications'])}")
    
    # Add overall metrics
    concise_results.append(f"\nOverall Performance:")
    concise_results.append(f"Accuracy: {metrics['accuracy']:.2%}")
    concise_results.append(f"Precision: {metrics['precision']:.2%}")
    concise_results.append(f"Recall: {metrics['recall']:.2%}")
    concise_results.append(f"F1 Score: {metrics['f1_score']:.2f}")
    
    # Add summary
    total_time = time.time() - start_time
    concise_results.append(f"\nSummary:")
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
    
    # Initialize counters
    total_score = 0
    total_files = 0
    results = []
    
    # Initialize classification counters
    classifications = {
        "true_positives_correct_packer": 0,
        "true_positives_wrong_packer": 0,
        "false_positives": 0,
        "true_negatives": 0,
        "false_negatives": 0
    }
    
    # Initialize packer statistics
    packer_stats = defaultdict(lambda: {
        "total": 0,
        "correctly_identified": 0,
        "wrong_identifications": set()
    })
    
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
                score, classification, actual_packer, detected_packer = calculate_score(file_path, result)
                total_score += score
                total_files += 1
                classifications[classification] += 1
                
                # Update packer statistics
                packer_stats[actual_packer]["total"] += 1
                if classification == "true_positives_correct_packer":
                    packer_stats[actual_packer]["correctly_identified"] += 1
                elif classification == "true_positives_wrong_packer" and detected_packer:
                    packer_stats[actual_packer]["wrong_identifications"].add(detected_packer)
            
            # Process not-packed file if available
            if i < len(not_packed_patterns):
                file_path = not_packed_patterns[i]
                log_debug(f"Processing not-packed file {i+1}/{len(not_packed_patterns)}: {file_path}")
                result = run_analysis(file_path)
                score, classification, actual_packer, detected_packer = calculate_score(file_path, result)
                total_score += score
                total_files += 1
                classifications[classification] += 1
                
                # Update packer statistics
                packer_stats[actual_packer]["total"] += 1
                if classification == "true_negatives":
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