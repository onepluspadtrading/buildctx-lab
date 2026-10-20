#!/usr/bin/env python3
# I67677 probe5: test builderv3 full gRPC method list (209 extracted) against the gateway
src = open('/probe.py').read().split("print('===I67677 PROBE START")[0]
ns = {}
exec(src, ns)
grpc_call = ns['grpc_call']
print('===I67677-P5 START===', flush=True)
# curated from the 209-method extraction + platform naming
cands = []
for m in ['BuildkitSolve', 'BuildkitStatus', 'CleanupSession', 'DiffSnapshots', 'DockerfilePrepare',
          'DownloadSnapshot', 'ImagePublish', 'InstallBuildDriver', 'NixpacksPrepare', 'PrepareSession',
          'RailpackPrepare', 'UnpackSnapshot', 'UploadSnapshot', 'StartBuild', 'StartSnapshotAndBuild',
          'StartSnapshot', 'WaitJob', 'Health', 'List', 'Get', 'Ping']:
    cands.append('/build_ext.BuildAgentApi/' + m)
    cands.append('/build_ext.Builder/' + m)
# a few others seen in the binary dump
cands += ['/moby.buildkit.secrets.v1.Secrets/GetSecret',
          '/moby.buildkit.v1.Control/DiskUsage', '/moby.buildkit.v1.Control/Info',
          '/moby.buildkit.v1.Control/ListWorkers', '/moby.buildkit.v1.Control/Solve',
          '/containerd.services.content.v1.Content/Info',
          '/containerd.services.content.v1.Content/ListStatuses',
          '/grpc.health.v1.Health/Watch', '/grpc.health.v1.Health/List',
          '/temporal.api.workflowservice.v1.WorkflowService/DescribeTaskQueue',
          '/temporal.api.workflowservice.v1.WorkflowService/ListTaskQueuePartitions',
          '/temporal.api.workflowservice.v1.WorkflowService/GetSearchAttributes',
          '/temporal.api.workflowservice.v1.WorkflowService/DescribeWorkflowExecution',
          '/temporal.api.workflowservice.v1.WorkflowService/CountWorkflowExecutions',
          '/temporal.api.workflowservice.v1.WorkflowService/ScanWorkflowExecutions',
          '/temporal.api.workflowservice.v1.WorkflowService/ListArchivedWorkflowExecutions',
          '/temporal.api.workflowservice.v1.WorkflowService/GetWorkerBuildIdCompatibility',
          '/temporal.api.workflowservice.v1.WorkflowService/DescribeBatchJob',
          '/temporal.api.workflowservice.v1.WorkflowService/ListBatchJobs',
          '/temporal.api.operatorservice.v1.OperatorService/ListSearchAttributes',
          '/temporal.api.operatorservice.v1.OperatorService/ListClusters',
          '/temporal.api.operatorservice.v1.OperatorService/GetCluster',
          '/temporal.api.operatorservice.v1.OperatorService/DescribeCluster',
          '/temporal.api.operatorservice.v1.OperatorService/ListNamespaces']
mapped = []
for p in cands:
    r = grpc_call(p, b'', timeout=5)
    tag = 'MAP' if r['st'] not in ('12', '-') else '--'
    print('%s|%s|http=%s|st=%s|len=%d' % (tag, p, r['http'], r['st'], r['n']), flush=True)
    if tag == 'MAP':
        mapped.append((p, r['st'], r['n']))
        if r['n'] and r['n'] < 4000:
            print('   B: ' + (ns['dump'](ns['frame_payload'](r['data'])) or '')[:300], flush=True)
print('MAPPED_N=%d %s' % (len(mapped), mapped), flush=True)
print('===I67677-P5 END===', flush=True)
