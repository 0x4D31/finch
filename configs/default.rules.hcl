# Finch default rule set
#
# This file is intentionally minimal so that Finch can be run immediately after
# cloning the repository without requiring additional services. By default, Finch
# will allow all traffic because the main configuration’s `default_action` is set
# to `allow`.
#
# To add your own policies, define rules here using the format described in
# `docs/rule-schema.md`. For example rules demonstrating each action, see
# `configs/example.rules.hcl`.

# No rules are defined in this file. Finch will apply the default action to all
# requests.