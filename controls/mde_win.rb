# frozen_string_literal: true

# copyright:: 2022, The Authors
# license: All rights reserved

title 'MDE Windows section'

mde_org_id = input('mde_org_id', value: false, description: 'Check mde use the correct Org ID')
mde_tags = input('mde_tags', value: false, description: 'Check mde use appropriate tags, BU, product.')

mde_dir = 'C:\Program Files\Windows Defender Advanced Threat Protection'
mde_bin = 'C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe'

control 'mdewin-1.0' do
  impact 1.0
  title 'mde should be present'
  desc 'Ensure mde executables and configuration are present'
  only_if { os.family == 'windows' }

  describe file(mde_dir) do
    it { should be_directory }
  end
  describe file(mde_bin) do
    it { should be_file }
  end
  # Win 2016 only. may be a more recent one
  # describe windows_hotfix('KB5005573') do
  #   it { should be_installed }
  # end
end

control 'mdewin-2.0' do
  impact 1.0
  title 'mde should be running'
  desc 'Ensure mde is running'
  only_if { os.family == 'windows' }
  describe service('Sense') do
    it { should be_installed }
    it { should be_enabled }
  end
end

control 'mdewin-3.0' do
  impact 1.0
  title 'mde should be configured'
  desc 'Appropriate setting should be configured'
  only_if { os.family == 'windows' }
  describe registry_key({
    hive: 'HKEY_LOCAL_MACHINE',
    key: 'SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\Status',
    }) do
    its('OnboardingState') { should eq '1' }
  end
  if mde_org_id
    describe registry_key({
      hive: 'HKEY_LOCAL_MACHINE',
      key: 'SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection',
      }) do
      its('OnboardingInfo') { should include mde_org_id }
    end
  end
  if mde_tags
    # https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/linux-preferences?view=o365-worldwide#add-tag-or-group-id-to-the-configuration-profile
    describe registry_key({
      hive: 'HKEY_LOCAL_MACHINE',
      key: 'SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging',
      }) do
      its('Group') { should eq mde_tags }
    end
  end
end
