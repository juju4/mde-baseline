# frozen_string_literal: true

# copyright:: 2022, The Authors
# license: All rights reserved

title 'MDE section'

mde_org_id = input('mde_org_id', value: false, description: 'Check mde use the correct Org ID')
mde_tags = input('mde_tags', value: false, description: 'Check mde use appropriate tags, BU, product.')
mde_proxy_host = input('mde_proxy_host', value: false, description: 'Check mde use appropriate proxy settings')
mde_proxy_port = input('mde_proxy_port', value: false, description: 'Check mde use appropriate proxy settings')
mde_version = input('mde_version', value: '101.62', description: 'Check mde version to be above or equal')
mde_managed = input('mde_managed', value: false, description: 'Check mde is in managed mode')
mde_passive_mode_enabled = input('mde_passive_mode_enabled', value: false, description: 'Check mde is set in passive mode')

mde_dir = '/opt/microsoft/mdatp'
if os.darwin?
  mde_mdatp_bin = '/opt/microsoft/mdatp/sbin/wdavdaemonclient'
  mde_bin = '/opt/microsoft/mdatp/sbin/wdavdaemon'
  mde_log1 = '/var/log/microsoft/mdatp/microsoft_defender.log'
  mde_log2 = '/var/log/microsoft/mdatp/microsoft_defender_core.log'
else
  mde_mdatp_path = '/usr/bin/mdatp'
  mde_mdatp_bin = '/opt/microsoft/mdatp/sbin/wdavdaemonclient'
  mde_bin = '/opt/microsoft/mdatp/sbin/wdavdaemon'
  mde_log1 = '/var/log/microsoft/mdatp/microsoft_defender.log'
  mde_log2 = '/var/log/microsoft/mdatp/microsoft_defender_core.log'
  mde_log3 = '/var/log/microsoft/mdatp/microsoft_defender_core_err.log'
end

control 'mde-1.0' do
  impact 1.0
  title 'mde should be present'
  desc 'Ensure mde executables and configuration are present'
  only_if { os.family != 'windows' }
  describe package('mdatp') do
    it { should be_installed }
    its('version') { should cmp >= mde_version }
  end
  describe file(mde_dir) do
    it { should be_directory }
  end
  describe file(mde_mdatp_path.to_s) do
    it { should be_symlink }
    it { should be_executable }
    it { should be_owned_by 'root' }
  end
  describe file(mde_mdatp_bin.to_s) do
    it { should be_file }
    its('mode') { should cmp '0755' }
    it { should be_owned_by 'root' }
  end
  describe file(mde_bin.to_s) do
    it { should be_file }
    its('mode') { should cmp '0755' }
    it { should be_executable }
    it { should be_owned_by 'root' }
  end
end

control 'mde-2.0' do
  impact 1.0
  title 'mde should be running'
  desc 'Ensure mde is running'
  only_if { !(virtualization.role == 'guest' && virtualization.system == 'docker') && os.family != 'windows' }
  describe service('mdatp') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
  describe processes('wdavdaemon') do
    # FIXME! non-deterministic order
    # its('users') { should eq %w[root root mdatp mdatp] }
    its('users') { should include 'root' }
    its('users') { should include 'mdatp' }
    its('entries.length') { should >= 3 }
  end
end

control 'mde-3.0' do
  impact 1.0
  title 'mde should be configured'
  desc 'Appropriate setting should be configured'
  only_if { !(virtualization.role == 'guest' && virtualization.system == 'docker') && os.family != 'windows' }
  if mde_org_id
    describe command('mdatp health --field org_id') do
      its('stdout') { should_not match 'Error' }
      its('stderr') { should_not match 'Error' }
      its('stdout') { should match mde_org_id }
    end
  end
  if mde_tags
    # https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/linux-preferences?view=o365-worldwide#add-tag-or-group-id-to-the-configuration-profile
    describe file('/etc/opt/microsoft/mdatp/managed/mdatp_managed.json') do
      it { should be_file }
      it { should be_owned_by 'root' }
      its('mode') { should cmp '0644' }
      its('content') { should match '"tags": ' }
      # FIXME: for each tag as likely different lines
      its('content') { should match '"tags": ' }
      if mde_proxy_host && mde_proxy_port
        its('content') { should include "\"proxy\": \"http://#{mde_proxy_host}:#{mde_proxy_port}\"" }
      end
    end
    describe command('python -m json.tool /etc/opt/microsoft/mdatp/managed/mdatp_managed.json') do
      its('stdout') { should_not match 'Error' }
      its('stderr') { should_not match 'Error' }
    end
  end
  if mde_proxy_host && mde_proxy_port
    # https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/linux-static-proxy-configuration?view=o365-worldwide
    describe file('/usr/lib/systemd/system/mdatp.service') do
      it { should be_file }
      it { should be_owned_by 'root' }
      its('mode') { should cmp '0644' }
      its('content') { should match "^Environment=\"HTTPS_PROXY=http://#{mde_proxy_host}:#{mde_proxy_port}\"" }
      # its('content') { should match '^EnvironmentFile=/etc/environment' }
      its('content') { should match '^Description=Microsoft Defender' }
    end
  end
  if mde_managed
    describe file('/etc/opt/microsoft/mdatp/managed/mdatp_managed.json') do
      it { should be_file }
      it { should be_owned_by 'root' }
      its('mode') { should cmp '0644' }
    end
    describe command('mdatp health') do
      its('stdout') { should include ' [managed]' }
    end
  end
end

control 'mde-3.1' do
  impact 1.0
  title 'mde should be in healthy state'
  desc 'Health check should be true'
  only_if { !(virtualization.role == 'guest' && virtualization.system == 'docker') && os.family != 'windows' }
  describe command('mdatp health --field healthy') do
    its('stdout') { should_not match 'Error' }
    its('stderr') { should_not match 'Error' }
    its('stdout') { should match 'true' }
  end
  describe command('mdatp health') do
    its('stdout') { should_not match 'Error' }
    its('stderr') { should_not match 'Error' }
    its('stdout') { should include 'health_issues                               : []' }
    its('stdout') { should include "passive_mode_enabled                        : #{mde_passive_mode_enabled}" }
    # TODO: check less than x minutes old?
    its('stdout') { should include 'definitions_updated_minutes_ago             :' }
    its('stdout') { should include 'definitions_status                          : "up_to_date"' }
  end
  describe command('mdatp connectivity test') do
    its('stdout') { should_not match 'Error' }
    its('stderr') { should_not match 'Error' }
    its('stdout') { should match 'Testing connection' }
    its('stdout') { should match 'OK' }
  end
  # issue on RHEL/Centos7. work with extra selinux configuration.
  if os.redhat?
    describe command('sestatus') do
      if os.release =~ /^8\./
        its('stdout') { should match 'enforcing' }
      else
        its('stdout') { should_not match 'enforcing' }
      end
      its('stderr') { should_not match 'Error' }
      its('stdout') { should match /SELinux status:.*enabled/ }
      its('stdout') { should match /Loaded policy name:.*targeted/ }
    end
    describe selinux do
      it { should be_installed }
      it { should_not be_disabled }
      # it { should be_enforcing }
      it { should_not be_permissive }
    end
  end
  # check mdatp auditd rules are present and loaded
  describe file('/opt/microsoft/mdatp/conf/mdatp.rules') do
    it { should be_file }
    its('mode') { should cmp '0644' }
    it { should be_owned_by 'root' }
    its('content') { should match '-k mdatpmbr' }
    its('content') { should match /-k mdatp$/ }
    # its('content') { should match 'Auditd rules for MDATP \(EDR\) audisp sensor' }
  end
  describe command('sudo auditctl -l | grep mdatp') do
    its('stdout') { should match /key=mdatp/ }
  end
  # /etc/audit/audit.rules (/etc/audit/rules.d/99-end.rules) '-e 2' issue immutable?
  describe file(mde_log3) do
    it { should be_file }
    it { should be_owned_by 'root' }
    its('mode') { should cmp '0660' }
    its('content') { should_not match "auditd_manager: Cloud exclusions won't be applied, because auditd is in lockdown mode. Restart required." }
    its('content') { should_not match 'Error connecting to server socket' }
  end
end

control 'mde-4.0' do
  impact 1.0
  title 'mde logs'
  desc 'Ensure mde logs exist and are written recently'
  only_if { !(virtualization.role == 'guest' && virtualization.system == 'docker') && os.family != 'windows' }
  describe file(mde_log1) do
    it { should be_file }
    it { should be_owned_by 'root' }
    its('mode') { should cmp '0660' }
  end
  describe file(mde_log2) do
    it { should be_file }
    it { should be_owned_by 'root' }
    its('mode') { should cmp '0660' }
  end
  describe file(mde_log2).mtime.to_i do
    it { should <= Time.now.to_i }
    it { should >= Time.now.to_i - 900 }
  end
end
