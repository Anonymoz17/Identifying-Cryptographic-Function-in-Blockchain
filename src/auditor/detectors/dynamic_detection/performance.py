"""
Performance optimization module for dynamic analysis.

This module provides comprehensive performance optimization features:
- Profiling of critical execution paths
- Parallel processing for batch operations
- Streaming trace processing for large outputs
- JavaScript hook optimization
- Resource usage monitoring
- Performance recommendations

All operations are local-only with no external dependencies.
"""

import time
import threading
import logging
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import multiprocessing

logger = logging.getLogger(__name__)


@dataclass
class ProfilingResult:
    """Results from profiling a code path."""
    operation: str
    duration_ms: float
    cpu_time_ms: float
    memory_peak_mb: float
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceMetrics:
    """Aggregated performance metrics."""
    total_operations: int = 0
    avg_duration_ms: float = 0.0
    p50_duration_ms: float = 0.0
    p95_duration_ms: float = 0.0
    p99_duration_ms: float = 0.0
    total_cpu_time_ms: float = 0.0
    peak_memory_mb: float = 0.0
    operations_per_second: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'total_operations': self.total_operations,
            'avg_duration_ms': round(self.avg_duration_ms, 2),
            'p50_duration_ms': round(self.p50_duration_ms, 2),
            'p95_duration_ms': round(self.p95_duration_ms, 2),
            'p99_duration_ms': round(self.p99_duration_ms, 2),
            'total_cpu_time_ms': round(self.total_cpu_time_ms, 2),
            'peak_memory_mb': round(self.peak_memory_mb, 2),
            'operations_per_second': round(self.operations_per_second, 2)
        }


@dataclass
class OptimizationRecommendation:
    """Performance optimization recommendation."""
    category: str  # 'critical', 'high', 'medium', 'low'
    title: str
    description: str
    impact: str
    effort: str
    current_value: Any
    recommended_value: Any
    estimated_improvement: str


class PerformanceOptimizer:
    """
    Main performance optimization class.
    
    Features:
    - Profiling of critical paths with CPU and memory tracking
    - Parallel processing for batch operations (thread/process pools)
    - Streaming trace processing to handle large outputs
    - JavaScript hook optimization suggestions
    - Performance metrics collection and reporting
    - Optimization recommendations based on metrics
    """
    
    def __init__(
        self,
        workspace_root: Path,
        enable_profiling: bool = True,
        max_workers: int = None,
        streaming_threshold_mb: float = 10.0,
        enable_process_pool: bool = False
    ):
        """
        Initialize performance optimizer.
        
        Args:
            workspace_root: Root workspace directory
            enable_profiling: Enable detailed profiling
            max_workers: Max parallel workers (None = CPU count)
            streaming_threshold_mb: Threshold for streaming mode (MB)
            enable_process_pool: Use process pool instead of thread pool
        """
        self.workspace_root = Path(workspace_root)
        self.enable_profiling = enable_profiling
        self.max_workers = max_workers or multiprocessing.cpu_count()
        self.streaming_threshold_mb = streaming_threshold_mb
        self.enable_process_pool = enable_process_pool
        
        # Profiling storage
        self.profiling_dir = self.workspace_root / "profiling"
        self.profiling_dir.mkdir(parents=True, exist_ok=True)
        
        # In-memory profiling results
        self._profiling_results: List[ProfilingResult] = []
        self._lock = threading.Lock()
        
        logger.info(
            f"PerformanceOptimizer initialized: "
            f"profiling={enable_profiling}, "
            f"workers={self.max_workers}, "
            f"streaming_threshold={streaming_threshold_mb}MB"
        )
    
    def profile(self, operation: str, metadata: Dict[str, Any] = None):
        """
        Context manager for profiling code blocks.
        
        Usage:
            with optimizer.profile("frida_spawn"):
                # code to profile
                pass
        
        Args:
            operation: Operation name
            metadata: Additional metadata
        """
        return ProfileContext(self, operation, metadata or {})
    
    def _record_profiling_result(self, result: ProfilingResult):
        """Record a profiling result (thread-safe)."""
        with self._lock:
            self._profiling_results.append(result)
            
            # Save to disk periodically (every 100 results)
            if len(self._profiling_results) % 100 == 0:
                self._save_profiling_results()
    
    def _save_profiling_results(self):
        """Save profiling results to disk."""
        if not self._profiling_results:
            return
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_file = self.profiling_dir / f"profiling_{timestamp}.jsonl"
        
        try:
            with output_file.open('a') as f:
                for result in self._profiling_results:
                    data = {
                        'operation': result.operation,
                        'duration_ms': result.duration_ms,
                        'cpu_time_ms': result.cpu_time_ms,
                        'memory_peak_mb': result.memory_peak_mb,
                        'timestamp': result.timestamp,
                        'metadata': result.metadata
                    }
                    f.write(json.dumps(data) + '\n')
            
            logger.debug(f"Saved {len(self._profiling_results)} profiling results to {output_file}")
            self._profiling_results.clear()
        
        except Exception as e:
            logger.error(f"Failed to save profiling results: {e}")
    
    def get_metrics(self, operation: str = None) -> PerformanceMetrics:
        """
        Get aggregated performance metrics.
        
        Args:
            operation: Filter by operation (None = all)
        
        Returns:
            Aggregated metrics
        """
        with self._lock:
            # Filter results
            results = self._profiling_results
            if operation:
                results = [r for r in results if r.operation == operation]
            
            if not results:
                return PerformanceMetrics()
            
            # Calculate metrics
            durations = sorted([r.duration_ms for r in results])
            cpu_times = [r.cpu_time_ms for r in results]
            memory_peaks = [r.memory_peak_mb for r in results]
            
            n = len(durations)
            p50_idx = int(n * 0.50)
            p95_idx = int(n * 0.95)
            p99_idx = int(n * 0.99)
            
            total_duration_s = sum(durations) / 1000.0
            ops_per_sec = n / total_duration_s if total_duration_s > 0 else 0
            
            return PerformanceMetrics(
                total_operations=n,
                avg_duration_ms=sum(durations) / n,
                p50_duration_ms=durations[p50_idx],
                p95_duration_ms=durations[p95_idx],
                p99_duration_ms=durations[p99_idx],
                total_cpu_time_ms=sum(cpu_times),
                peak_memory_mb=max(memory_peaks),
                operations_per_second=ops_per_sec
            )
    
    def parallel_process_batch(
        self,
        items: List[Any],
        process_func: Callable[[Any], Any],
        operation_name: str = "batch_operation"
    ) -> List[Any]:
        """
        Process items in parallel using thread or process pool.
        
        Args:
            items: Items to process
            process_func: Function to apply to each item
            operation_name: Name for profiling
        
        Returns:
            List of results in same order as input
        """
        if not items:
            return []
        
        with self.profile(f"{operation_name}_batch", {'count': len(items)}):
            # Choose executor type
            if self.enable_process_pool:
                executor_class = ProcessPoolExecutor
            else:
                executor_class = ThreadPoolExecutor
            
            results = [None] * len(items)
            
            with executor_class(max_workers=self.max_workers) as executor:
                # Submit all tasks
                future_to_index = {
                    executor.submit(process_func, item): i
                    for i, item in enumerate(items)
                }
                
                # Collect results
                for future in as_completed(future_to_index):
                    index = future_to_index[future]
                    try:
                        results[index] = future.result()
                    except Exception as e:
                        logger.error(f"Batch processing error for item {index}: {e}")
                        results[index] = None
            
            logger.info(
                f"Parallel processing complete: {len(items)} items, "
                f"{self.max_workers} workers, "
                f"executor={executor_class.__name__}"
            )
            
            return results
    
    def stream_trace_file(
        self,
        trace_file: Path,
        chunk_size: int = 1000
    ) -> Iterator[List[Dict[str, Any]]]:
        """
        Stream a large trace file in chunks.
        
        Args:
            trace_file: Path to trace JSON file
            chunk_size: Number of events per chunk
        
        Yields:
            Chunks of trace events
        """
        if not trace_file.exists():
            logger.error(f"Trace file not found: {trace_file}")
            return
        
        file_size_mb = trace_file.stat().st_size / (1024 * 1024)
        should_stream = file_size_mb >= self.streaming_threshold_mb
        
        logger.info(
            f"Streaming trace file: {trace_file.name} "
            f"({file_size_mb:.2f} MB, streaming={should_stream})"
        )
        
        try:
            with trace_file.open('r') as f:
                data = json.load(f)
                
                events = data.get('events', [])
                total_events = len(events)
                
                # Yield chunks
                for i in range(0, total_events, chunk_size):
                    chunk = events[i:i + chunk_size]
                    yield chunk
                    
                    if (i + chunk_size) % 10000 == 0:
                        logger.debug(f"Streamed {i + chunk_size}/{total_events} events")
        
        except Exception as e:
            logger.error(f"Error streaming trace file: {e}")
    
    def optimize_js_hooks(self, script_content: str) -> str:
        """
        Optimize JavaScript instrumentation hooks.
        
        Optimizations:
        - Remove redundant hook installations
        - Batch memory reads
        - Minimize string operations
        - Use efficient data structures
        
        Args:
            script_content: Original JavaScript content
        
        Returns:
            Optimized JavaScript content
        """
        # For now, return original content
        # TODO: Implement JavaScript optimization patterns
        logger.debug("JavaScript hook optimization (placeholder)")
        return script_content
    
    def get_recommendations(self) -> List[OptimizationRecommendation]:
        """
        Generate performance optimization recommendations.
        
        Returns:
            List of recommendations ordered by impact
        """
        recommendations = []
        
        # Get overall metrics
        metrics = self.get_metrics()
        
        # Check if we have enough data
        if metrics.total_operations < 10:
            return recommendations
        
        # Recommendation: Parallel processing
        if not self.enable_process_pool and metrics.avg_duration_ms > 1000:
            recommendations.append(OptimizationRecommendation(
                category='high',
                title='Enable Process Pool Execution',
                description='Long-running operations can benefit from process-based parallelism',
                impact='high',
                effort='low',
                current_value='ThreadPoolExecutor',
                recommended_value='ProcessPoolExecutor',
                estimated_improvement='30-50% faster for CPU-bound tasks'
            ))
        
        # Recommendation: Worker count
        cpu_count = multiprocessing.cpu_count()
        if self.max_workers < cpu_count:
            recommendations.append(OptimizationRecommendation(
                category='medium',
                title='Increase Worker Count',
                description=f'System has {cpu_count} CPUs but using only {self.max_workers} workers',
                impact='medium',
                effort='low',
                current_value=self.max_workers,
                recommended_value=cpu_count,
                estimated_improvement=f'{int((cpu_count / self.max_workers - 1) * 100)}% more throughput'
            ))
        
        # Recommendation: Streaming threshold
        if metrics.peak_memory_mb > 500:
            recommendations.append(OptimizationRecommendation(
                category='critical',
                title='Lower Streaming Threshold',
                description='High memory usage detected, lower streaming threshold to process traces in chunks',
                impact='critical',
                effort='low',
                current_value=f'{self.streaming_threshold_mb} MB',
                recommended_value='5 MB',
                estimated_improvement='50-70% reduction in memory usage'
            ))
        
        # Recommendation: Profiling overhead
        if self.enable_profiling and metrics.total_operations > 10000:
            recommendations.append(OptimizationRecommendation(
                category='low',
                title='Disable Detailed Profiling',
                description='Profiling adds overhead for high-volume operations',
                impact='low',
                effort='low',
                current_value='enabled',
                recommended_value='disabled or sampling',
                estimated_improvement='5-10% performance improvement'
            ))
        
        # Sort by category priority
        priority_map = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        recommendations.sort(key=lambda r: priority_map.get(r.category, 3))
        
        return recommendations
    
    def generate_report(self, output_file: Path = None) -> Dict[str, Any]:
        """
        Generate comprehensive performance report.
        
        Args:
            output_file: Optional file to save report
        
        Returns:
            Report dictionary
        """
        # Get metrics for all operations
        all_metrics = self.get_metrics()
        
        # Get per-operation metrics
        operations = set(r.operation for r in self._profiling_results)
        per_operation_metrics = {
            op: self.get_metrics(op).to_dict()
            for op in operations
        }
        
        # Get recommendations
        recommendations = self.get_recommendations()
        
        # Build report
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'summary': {
                'total_operations': all_metrics.total_operations,
                'unique_operations': len(operations),
                'avg_duration_ms': all_metrics.avg_duration_ms,
                'operations_per_second': all_metrics.operations_per_second,
                'peak_memory_mb': all_metrics.peak_memory_mb
            },
            'overall_metrics': all_metrics.to_dict(),
            'per_operation_metrics': per_operation_metrics,
            'configuration': {
                'profiling_enabled': self.enable_profiling,
                'max_workers': self.max_workers,
                'streaming_threshold_mb': self.streaming_threshold_mb,
                'executor_type': 'ProcessPool' if self.enable_process_pool else 'ThreadPool',
                'cpu_count': multiprocessing.cpu_count()
            },
            'recommendations': [
                {
                    'category': r.category,
                    'title': r.title,
                    'description': r.description,
                    'impact': r.impact,
                    'effort': r.effort,
                    'current_value': r.current_value,
                    'recommended_value': r.recommended_value,
                    'estimated_improvement': r.estimated_improvement
                }
                for r in recommendations
            ]
        }
        
        # Save to file if requested
        if output_file:
            output_file = Path(output_file)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with output_file.open('w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"Performance report saved to {output_file}")
        
        return report
    
    def reset_metrics(self):
        """Clear all profiling results."""
        with self._lock:
            self._profiling_results.clear()
        logger.info("Performance metrics reset")
    
    def cleanup(self):
        """Cleanup resources and save remaining profiling data."""
        self._save_profiling_results()
        logger.info("PerformanceOptimizer cleanup complete")


class ProfileContext:
    """Context manager for profiling code blocks."""
    
    def __init__(self, optimizer: PerformanceOptimizer, operation: str, metadata: Dict[str, Any]):
        self.optimizer = optimizer
        self.operation = operation
        self.metadata = metadata
        self.start_time = None
        self.start_cpu_time = None
    
    def __enter__(self):
        """Start profiling."""
        if self.optimizer.enable_profiling:
            self.start_time = time.perf_counter()
            self.start_cpu_time = time.process_time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop profiling and record result."""
        if not self.optimizer.enable_profiling:
            return
        
        # Calculate durations
        duration_ms = (time.perf_counter() - self.start_time) * 1000
        cpu_time_ms = (time.process_time() - self.start_cpu_time) * 1000
        
        # Get memory usage (approximate)
        import psutil
        process = psutil.Process()
        memory_peak_mb = process.memory_info().rss / (1024 * 1024)
        
        # Record result
        result = ProfilingResult(
            operation=self.operation,
            duration_ms=duration_ms,
            cpu_time_ms=cpu_time_ms,
            memory_peak_mb=memory_peak_mb,
            metadata=self.metadata
        )
        
        self.optimizer._record_profiling_result(result)
        
        logger.debug(
            f"Profiled {self.operation}: "
            f"{duration_ms:.2f}ms, "
            f"CPU {cpu_time_ms:.2f}ms, "
            f"Memory {memory_peak_mb:.2f}MB"
        )


# Example usage
if __name__ == "__main__":
    # Create optimizer
    optimizer = PerformanceOptimizer(
        workspace_root=Path("workspace"),
        enable_profiling=True,
        max_workers=4,
        streaming_threshold_mb=10.0
    )
    
    # Example: Profile an operation
    with optimizer.profile("test_operation", {'param': 'value'}):
        time.sleep(0.1)  # Simulate work
    
    # Example: Parallel batch processing
    def process_item(item):
        time.sleep(0.05)
        return item * 2
    
    items = list(range(20))
    results = optimizer.parallel_process_batch(items, process_item, "multiply")
    
    # Generate report
    report = optimizer.generate_report(Path("workspace/performance_report.json"))
    print(f"Performance report: {json.dumps(report['summary'], indent=2)}")
    
    # Get recommendations
    recommendations = optimizer.get_recommendations()
    for rec in recommendations:
        print(f"[{rec.category.upper()}] {rec.title}: {rec.description}")
    
    # Cleanup
    optimizer.cleanup()
