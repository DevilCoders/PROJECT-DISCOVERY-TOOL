# ROS 1 and ROS 2 Intelligence

The initial ROS analyzer recognizes package.xml manifests, selected CMake package
references, ROS Python client imports and node inheritance (Python node classes and API calls
count only in files that import rclpy or rospy), common publisher /
subscription / service / action API call sites, C++ ROS includes and templated
communication calls, launch-description file presence, and .msg/.srv/.action
interface files.

ROS package dependencies are used to classify likely ROS 1 and ROS 2 ecosystems.
A package may contain both, neither, or mixed dependencies; this is a static
classification, not runtime discovery.

Important limitations:
- No ROS nodes are launched and no ROS master, DDS graph, or running system is contacted.
- Topic and service strings are reported only when literal arguments can be extracted.
- Dynamic topic names, remapping, namespaces, launch substitutions, QoS compatibility,
  lifecycle state, message type resolution, and inter-process topology are not inferred.
- Launch files are currently inventoried rather than fully evaluated.
- Interface files are counted as text definitions; field types and dependency chains
  are not yet resolved.
