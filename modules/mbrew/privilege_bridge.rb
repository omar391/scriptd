# Loaded with Ruby -r before Homebrew defines SystemCommand.
# On the inspected Homebrew version, non-developer startup unsets
# HOMEBREW_RUBY_WARNINGS. Scriptd may set HOMEBREW_DEVELOPER temporarily only
# for Ruby preloading, with HOMEBREW_NO_AUTO_UPDATE set, then clear its marker
# and developer flags as soon as SystemCommand is defined. Verify this behavior
# against the installed Homebrew before allowing broker execution.

module ScriptdPrivilegeBridge
  def sudo_prefix(*)
    client = ENV["HOMEBREW_SCRIPTD_PRIVILEGE_CLIENT"].to_s
    job = ENV["HOMEBREW_SCRIPTD_PRIVILEGE_JOB"].to_s
    token = ENV["HOMEBREW_SCRIPTD_PRIVILEGE_TOKEN"].to_s
    return super if client.empty? || job.empty? || token.empty?

    [client, "broker", "exec", "--job", job, "--token", token, "--"]
  end
end

TracePoint.trace(:end) do |point|
  next unless point.self.is_a?(Module) && point.self.name == "SystemCommand"

  if point.self.method_defined?(:sudo_prefix) || point.self.private_method_defined?(:sudo_prefix)
    point.self.prepend(ScriptdPrivilegeBridge)
    ENV["SCRIPTD_PRIVILEGE_BRIDGE_ATTACHED"] = "1"
    if ENV.delete("HOMEBREW_SCRIPTD_TEMP_DEVELOPER") == "1"
      ENV.delete("HOMEBREW_DEVELOPER")
      ENV.delete("HOMEBREW_DEV_CMD_RUN")
    end
  else
    ENV["SCRIPTD_PRIVILEGE_BRIDGE_ATTACHED"] = "missing"
  end
  point.disable
end
