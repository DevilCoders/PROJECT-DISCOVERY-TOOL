# AI/ML and Robotics Analysis

## AI/ML intelligence (initial implementation)
The built-in AI/ML analyzer statically identifies common framework imports in Python
source, training/inference/data-pipeline call markers, accelerator/device references,
selected model metadata JSON, and model/dataset artifact file types. Jupyter notebooks are read statically: their code cells form one module (IPython `%` magics, `!` shell lines and `?` help lines are skipped), and evidence names the cell and line (`train.ipynb:cell 3 line 1`).

It does not import ML frameworks, deserialize checkpoints, execute notebooks, read
binary tensor payloads, inspect model weights, infer a complete neural architecture,
or claim that training/inference actually ran. Source call markers are heuristic
(INFERRED); observed imports and recognized artifact paths are evidence of their
presence only (CONFIRMED). This is an initial domain implementation, not full ML
architecture or dataset lineage analysis.

## Robotics and ROS
The ROS analyzer (`ros-intelligence`) classifies ROS 1 and ROS 2 packages from
`package.xml` dependencies and inventories Python and C++ node APIs, publisher,
subscription, service and action call sites with literal topic names, launch files
and `.msg`/`.srv`/`.action` interfaces. See [ROS_ANALYZER.md](ROS_ANALYZER.md) for
its scope and limits. File names alone are never reported as confirmed runtime
communication graphs, and QoS, remapping and runtime discovery are not inferred.
