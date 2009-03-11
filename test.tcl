set msg 26
set user test
set password test
# Connect to INBOX mailbox on localhost
set mailbox {{localhost}}
set id [ns_imap open -mailbox $mailbox -user $user -password $password]
ns_log Debug [ns_imap status $id]

if { [ns_imap n_msgs $id] > $msg } {
  ns_log Debug From [ns_imap header $id $msg from] about [ns_imap header $id $msg subject]
  foreach { name value } [ns_imap headers $id $msg] {
    ns_log Debug HEADER: $name: $value
  }
  foreach { name value } [ns_imap struct $id $msg] {
    if { [string range $name 0 3] == "part" } {
      set no [string range $name 4 end]
      foreach { name value } $value {
        ns_log Debug PART$no: $name: $value
      }
      continue
    }
    ns_log Debug $name: $value
  }
}
