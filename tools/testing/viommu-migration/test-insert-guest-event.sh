#! /bin/bash

echo 'func __iommu_queue_command_sync +p' > /sys/kernel/debug/dynamic_debug/control
echo "--- insert ---" > /dev/kmsg && echo $1 > /sys/kernel/debug/iommu/amd/iommu00/guest_event && echo "--- end ---" > /dev/kmsg
echo 'func __iommu_queue_command_sync -p' > /sys/kernel/debug/dynamic_debug/control

