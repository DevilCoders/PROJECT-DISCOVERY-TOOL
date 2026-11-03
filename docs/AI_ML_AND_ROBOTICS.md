# AI/ML and Robotics Analysis

## AI/ML intelligence (initial implementation)
The built-in AI/ML analyzer statically identifies common framework imports in Python
source, training/inference/data-pipeline call markers, accelerator/device references,
selected model metadata JSON, and model/dataset artifact file types.

It does not import ML frameworks, deserialize checkpoints, execute notebooks, read
binary tensor payloads, inspect model weights, infer a complete neural architecture,
or claim that training/inference actually ran. Source call markers are heuristic
(INFERRED); observed imports and recognized artifact paths are evidence of their
presence only (CONFIRMED). This is an initial domain implementation, not full ML
architecture or dataset lineage analysis.

## Robotics and ROS
ROS coverage remains planned until the dedicated ROS analyzer is implemented and
tested. Future work must distinguish ROS 1 and ROS 2, static package metadata,
nodes/topics/services/actions, launch descriptions, message/service/action
interfaces, QoS and runtime discovery. File names alone must not be reported as
confirmed runtime communication graphs.
