use super::{fields, FieldInfo};

// Container fields are supplied by the container plugin rather than a
// libsinsp filtercheck table in libs 0.26.0-rc1.
pub(super) const FIELDS: &[FieldInfo] = fields!(Container;
    ("container.cni.json", "Container CNI Result"),
    ("container.created_time", "Container Creation Time"),
    ("container.duration", "Container Duration"),
    ("container.healthcheck", "Container Health Check"),
    ("container.id", "Container ID"),
    ("container.image", "Container Image"),
    ("container.image.digest", "Container Image Digest"),
    ("container.image.id", "Container Image ID"),
    ("container.image.repository", "Container Image Repository"),
    ("container.image.tag", "Container Image Tag"),
    ("container.ip", "Container IP"),
    ("container.mount", "Container Mount"),
    ("container.mounts", "Container Mounts"),
    ("container.name", "Container Name"),
    ("container.privileged", "Privileged Container"),
    ("container.type", "Container Type"),
);
