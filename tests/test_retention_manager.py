"""
Tests for retention manager.

Tests automatic cleanup, compression, and storage management.

Author: Dynamic Analysis Team
Date: November 11, 2025
"""

import pytest
import json
import gzip
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from src.auditor.detectors.dynamic_detection.retention_manager import (
    RetentionManager,
    RetentionConfig,
    RetentionPeriod,
    CleanupAuditEntry,
    run_scheduled_cleanup
)


@pytest.fixture
def test_workspace(tmp_path):
    """Create temporary workspace structure."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    
    analysis_dir = workspace / "analysis" / "dynamic"
    analysis_dir.mkdir(parents=True)
    
    return workspace


@pytest.fixture
def create_test_result(test_workspace):
    """Factory for creating test results."""
    analysis_dir = test_workspace / "analysis" / "dynamic"
    
    def _create(file_hash: str, age_days: int, has_crypto: bool = False, incomplete: bool = False):
        """Create test result with specific age."""
        result_dir = analysis_dir / file_hash
        result_dir.mkdir()
        
        # Create results file
        results = {
            'file_hash': file_hash,
            'timestamp': datetime.now().isoformat(),
            'incomplete': incomplete,
            'summary': {
                'crypto_calls': 15 if has_crypto else 0
            }
        }
        
        results_path = result_dir / "dynamic_results.json"
        with open(results_path, 'w') as f:
            json.dump(results, f)
        
        # Create trace file
        trace_path = result_dir / "trace.ndjson"
        with open(trace_path, 'w') as f:
            for i in range(100):
                f.write(json.dumps({'event': f'event_{i}'}) + '\n')
        
        # Set modification time to simulate age
        if age_days > 0:
            old_time = (datetime.now() - timedelta(days=age_days)).timestamp()
            os.utime(results_path, (old_time, old_time))
        
        return result_dir
    
    return _create


class TestRetentionManager:
    """Test retention manager."""
    
    def test_initialization(self, test_workspace):
        """Test manager initialization."""
        manager = RetentionManager(str(test_workspace))
        
        assert manager.workspace_dir == Path(test_workspace)
        assert (test_workspace / "retention").exists()
        assert (test_workspace / "retention" / "config.json").exists()
    
    def test_custom_config(self, test_workspace):
        """Test custom configuration."""
        config = RetentionConfig(
            default_retention_days=14,
            compression_after_days=7,
            enable_compression=True
        )
        
        manager = RetentionManager(str(test_workspace), config=config)
        
        assert manager.config.default_retention_days == 14
        assert manager.config.compression_after_days == 7
    
    def test_cleanup_old_results(self, test_workspace, create_test_result):
        """Test cleanup of old results."""
        # Create results of different ages
        create_test_result('hash_old', age_days=45)  # Should be deleted
        create_test_result('hash_recent', age_days=10)  # Should be kept
        create_test_result('hash_new', age_days=1)  # Should be kept
        
        manager = RetentionManager(str(test_workspace))
        stats = manager.run_cleanup(dry_run=False)
        
        assert stats['files_scanned'] == 3
        assert stats['files_deleted'] == 1
        assert stats['bytes_freed'] > 0
        
        analysis_dir = test_workspace / "analysis" / "dynamic"
        assert not (analysis_dir / "hash_old").exists()
        assert (analysis_dir / "hash_recent").exists()
        assert (analysis_dir / "hash_new").exists()
    
    def test_dry_run(self, test_workspace, create_test_result):
        """Test dry run mode."""
        create_test_result('hash_old', age_days=45)
        
        manager = RetentionManager(str(test_workspace))
        stats = manager.run_cleanup(dry_run=True)
        
        # Should report but not delete
        assert stats['files_scanned'] == 1
        assert stats['files_deleted'] == 0
        
        analysis_dir = test_workspace / "analysis" / "dynamic"
        assert (analysis_dir / "hash_old").exists()
    
    def test_high_confidence_retention(self, test_workspace, create_test_result):
        """Test longer retention for high-confidence results."""
        # Create result with high crypto calls
        create_test_result('hash_crypto', age_days=45, has_crypto=True)
        
        manager = RetentionManager(str(test_workspace))
        stats = manager.run_cleanup(dry_run=False)
        
        # Should be kept (45 days < 90 days for high confidence)
        assert stats['files_deleted'] == 0
        
        analysis_dir = test_workspace / "analysis" / "dynamic"
        assert (analysis_dir / "hash_crypto").exists()
    
    def test_incomplete_result_cleanup(self, test_workspace, create_test_result):
        """Test short retention for incomplete results."""
        # Create incomplete result
        create_test_result('hash_incomplete', age_days=10, incomplete=True)
        
        manager = RetentionManager(str(test_workspace))
        stats = manager.run_cleanup(dry_run=False)
        
        # Should be deleted (10 days > 7 days for incomplete)
        assert stats['files_deleted'] == 1
        
        analysis_dir = test_workspace / "analysis" / "dynamic"
        assert not (analysis_dir / "hash_incomplete").exists()
    
    def test_trace_compression(self, test_workspace, create_test_result):
        """Test trace file compression."""
        result_dir = create_test_result('hash_compress', age_days=20)
        trace_path = result_dir / "trace.ndjson"
        original_size = trace_path.stat().st_size
        
        manager = RetentionManager(str(test_workspace))
        stats = manager.compress_old_traces(days=15)
        
        assert stats['files_compressed'] == 1
        assert stats['bytes_saved'] > 0
        
        # Original deleted, compressed exists
        assert not trace_path.exists()
        assert (result_dir / "trace.ndjson.gz").exists()
        
        # Compressed size should be smaller
        compressed_size = (result_dir / "trace.ndjson.gz").stat().st_size
        assert compressed_size < original_size
    
    def test_no_double_compression(self, test_workspace, create_test_result):
        """Test that already compressed files are not compressed again."""
        result_dir = create_test_result('hash_already', age_days=20)
        
        # Compress once
        manager = RetentionManager(str(test_workspace))
        manager.compress_old_traces(days=15)
        
        # Try to compress again
        stats = manager.compress_old_traces(days=15)
        
        # Should report no compressions
        assert stats['files_compressed'] == 0
    
    def test_storage_stats(self, test_workspace, create_test_result):
        """Test storage statistics calculation."""
        create_test_result('hash1', age_days=5)
        create_test_result('hash2', age_days=20)
        create_test_result('hash3', age_days=50)
        create_test_result('hash4', age_days=100)
        
        manager = RetentionManager(str(test_workspace))
        stats = manager.get_storage_stats()
        
        assert stats['total_results'] == 4
        assert stats['total_size_bytes'] > 0
        assert stats['by_age']['0-7d']['count'] == 1
        assert stats['by_age']['7-30d']['count'] == 1
        assert stats['by_age']['30-90d']['count'] == 1
        assert stats['by_age']['90d+']['count'] == 1
    
    def test_retention_report(self, test_workspace, create_test_result):
        """Test retention report generation."""
        create_test_result('hash1', age_days=5)
        create_test_result('hash2', age_days=20)
        
        manager = RetentionManager(str(test_workspace))
        report = manager.get_retention_report()
        
        assert 'timestamp' in report
        assert 'config' in report
        assert 'storage' in report
        assert 'recommendations' in report
    
    def test_force_cleanup_by_size(self, test_workspace, create_test_result):
        """Test force cleanup to reach target size."""
        # Create multiple results
        create_test_result('hash1', age_days=5)
        create_test_result('hash2', age_days=20)
        create_test_result('hash3', age_days=50)
        create_test_result('hash4', age_days=100)
        
        manager = RetentionManager(str(test_workspace))
        
        # Force cleanup to very small size
        stats = manager.force_cleanup_by_size(target_size_gb=0.00001)
        
        # Should delete oldest first
        assert stats['files_deleted'] > 0
        
        analysis_dir = test_workspace / "analysis" / "dynamic"
        
        # Oldest should be deleted first
        assert not (analysis_dir / "hash4").exists()
    
    def test_preserve_patterns(self, test_workspace, create_test_result):
        """Test preservation of specific patterns."""
        result_dir = create_test_result('important_hash', age_days=100)
        
        config = RetentionConfig(
            preserve_patterns=['*important*']
        )
        
        manager = RetentionManager(str(test_workspace), config=config)
        stats = manager.run_cleanup(dry_run=False)
        
        # Should be preserved despite age
        assert stats['files_preserved'] == 1
        assert result_dir.exists()
    
    def test_audit_logging(self, test_workspace, create_test_result):
        """Test audit log creation."""
        create_test_result('hash_log', age_days=45)
        
        manager = RetentionManager(str(test_workspace))
        manager.run_cleanup(dry_run=False)
        
        audit_log = test_workspace / "retention" / "cleanup_audit.jsonl"
        assert audit_log.exists()
        
        # Read audit log
        with open(audit_log, 'r') as f:
            lines = f.readlines()
        
        assert len(lines) > 0
        
        entry = json.loads(lines[0])
        assert entry['action'] == 'delete'
        assert 'hash_log' in entry['file_path']
    
    def test_concurrent_operations(self, test_workspace, create_test_result):
        """Test thread safety."""
        import threading
        
        for i in range(10):
            create_test_result(f'hash_{i}', age_days=i * 5)
        
        manager = RetentionManager(str(test_workspace))
        
        results = []
        
        def run_cleanup():
            stats = manager.run_cleanup(dry_run=False)
            results.append(stats)
        
        threads = [threading.Thread(target=run_cleanup) for _ in range(3)]
        
        for t in threads:
            t.start()
        
        for t in threads:
            t.join()
        
        # Should complete without errors
        assert len(results) == 3


def test_scheduled_cleanup(test_workspace, create_test_result):
    """Test scheduled cleanup function."""
    create_test_result('hash1', age_days=5)
    create_test_result('hash2', age_days=45)
    
    stats = run_scheduled_cleanup(str(test_workspace), dry_run=False)
    
    assert stats['files_scanned'] == 2
    assert stats['files_deleted'] == 1
