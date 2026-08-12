"""Format-specific pipeline normalizers.

Each normalizer converts a redacted pipeline definition text into a
validated PipelineIR instance.  Normalizers must never make outbound
HTTP requests — unresolvable constructs are recorded as Not Assessable.
"""
