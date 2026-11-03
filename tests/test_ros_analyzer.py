from pathlib import Path

from project_discovery.analyzers.ros_analyzer import ROSIntelligenceAnalyzer
from project_discovery.models import FileRecord


def _record(path: Path, relative: str) -> FileRecord:
    return FileRecord(relative, path.stat().st_size, path.suffix.lower(), "Unknown")


def test_ros2_python_node_and_communication_apis(tmp_path: Path):
    path = tmp_path / "talker_node.py"
    path.write_text(
        "import rclpy\nfrom rclpy.node import Node\n"
        "class Talker(Node):\n    def __init__(self):\n"
        "        self.pub = self.create_publisher(String, '/chatter', 10)\n"
        "        self.sub = self.create_subscription(String, '/input', cb, 10)\n"
        "        self.srv = self.create_service(Trigger, '/reset', cb)\n",
        encoding="utf-8",
    )
    analyzer = ROSIntelligenceAnalyzer()
    record = _record(path, "talker_node.py")
    assert analyzer.supports(record)
    findings = analyzer.analyze(path, record)
    assert any("ROS framework imports" in item.title for item in findings)
    communication = next(item for item in findings if "communication API" in item.title)
    assert "/chatter" in repr(communication.to_dict())
    assert "/input" in repr(communication.to_dict())


def test_ros_package_xml_distinguishes_ros1_and_ros2(tmp_path: Path):
    path = tmp_path / "package.xml"
    path.write_text(
        "<package><name>robot_stack</name><version>1.0</version>"
        "<buildtool_depend>ament_cmake</buildtool_depend>"
        "<depend>rclcpp</depend><exec_depend>sensor_msgs</exec_depend></package>",
        encoding="utf-8",
    )
    findings = ROSIntelligenceAnalyzer().analyze(path, _record(path, "package.xml"))
    assert len(findings) == 1
    assert "ROS 2" in findings[0].detail
    assert "robot_stack" in findings[0].title


def test_ros_interfaces_and_launch_files_are_inventoried(tmp_path: Path):
    interface = tmp_path / "MoveRobot.action"
    interface.write_text(
        "float64 x\n---\nbool success\n---\nstring message\n",
        encoding="utf-8",
    )
    findings = ROSIntelligenceAnalyzer().analyze(
        interface, _record(interface, "action/MoveRobot.action")
    )
    assert findings[0].category == "robotics"
    assert "3 non-comment definition lines" in findings[0].detail

    launch = tmp_path / "bringup.launch.py"
    launch.write_text("from launch import LaunchDescription\n", encoding="utf-8")
    analyzer = ROSIntelligenceAnalyzer()
    record = _record(launch, "launch/bringup.launch.py")
    assert analyzer.supports(record)
    assert analyzer.analyze(launch, record)[0].title.startswith("ROS launch description")


def test_non_ros_python_is_not_supported(tmp_path: Path):
    path = tmp_path / "ordinary.py"
    path.write_text("print('hello')", encoding="utf-8")
    assert ROSIntelligenceAnalyzer().supports(_record(path, "utils/ordinary.py")) is False


def test_malformed_ros_package_is_unknown(tmp_path: Path):
    path = tmp_path / "package.xml"
    path.write_text("<package>", encoding="utf-8")
    findings = ROSIntelligenceAnalyzer().analyze(path, _record(path, "package.xml"))
    assert findings[0].confidence == "UNKNOWN"
