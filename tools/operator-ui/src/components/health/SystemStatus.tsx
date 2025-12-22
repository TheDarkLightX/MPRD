/**
 * System Status Grid
 * 
 * Displays all MPRD components in a grid layout.
 */

import type { SystemStatus } from '../../api/types';
import { ComponentCard, SystemStatusHeader } from './ComponentCard';
import { Card } from '../ui';
import { Binary, HardDrive, Shield, Zap } from 'lucide-react';

interface SystemStatusGridProps {
    status: SystemStatus;
}

export function SystemStatusGrid({ status }: SystemStatusGridProps) {
    return (
        <Card padding="lg">
            <SystemStatusHeader status={status.overall} />

            <div className="mt-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <ComponentCard
                    name="Tau Language"
                    health={status.components.tau}
                    icon={<Binary className="w-5 h-5" />}
                />
                <ComponentCard
                    name="IPFS Storage"
                    health={status.components.ipfs}
                    icon={<HardDrive className="w-5 h-5" />}
                />
                <ComponentCard
                    name="Risc0 ZK"
                    health={status.components.risc0}
                    icon={<Shield className="w-5 h-5" />}
                />
                <ComponentCard
                    name="Executor"
                    health={status.components.executor}
                    icon={<Zap className="w-5 h-5" />}
                />
            </div>
        </Card>
    );
}
