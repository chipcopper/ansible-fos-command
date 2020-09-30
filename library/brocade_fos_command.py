#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020 Chip Copper <chip.copper@broadcom.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" Ansible module to allow CLI commands to be run from inside of playbooks """

import sys
import time
import socket
import re
import paramiko
from ansible.module_utils.basic import AnsibleModule


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: brocade_fos_command
short_description: This module enables SAN automation through the FOS CLI.
description:
    - This modules provides a mechanism for executing FOS commands via an Ansible task.
    - Each task will be a separate virtual terminal session.
    - One or more commands may be executed in each task.
    - Each command begins by sending the CLI command as it would be entered at a system prompt.
    - The module then waits for responses.  Each response is examined to see if it contains
    - the prompt, an exit string, or a dialog question.  An exit string is something other than the prompt that
    - indicates that the session should be ended.  An example of this is when the firmwaredownload
    - command is executed.  The system does not return to the prompt but instead returns a
    - response saying Rebooting. A dialog question is prompting for further user input.  A typical
    - example is when a command has additional required parameters that cannot be provided as
    - CLI flags or when the system is asking for confirmation a la "Are you sure you want to reboot?"
    - Returning to the prompt indicated that the command has completed.
    - The module includes a configurable timeout value so that if an unexpected response comes from
    - the switch, the module will not hang indefinately.
    - The module also provides the ability to indicate if the command has changed the state of the
    - switch.  Since some commands affirm on change and others affirm on no change, it is up to
    - the user to indicate when change has and has not occurred.  Brocade will be providing
    - examples for many commands to indicate which options should be used with which commands.

version_added: "9.30.20.1"
author: "Chip Copper (chip.copper@broadcom.com)""
options:
    switch_login:
        description:
            - Account name under which commands should be run.
        required: True
    switch_password:
        description:
            - Password for the account.
        required: True
    switch_address:
        description:
            - IP address or logical name of the switch to be managed.
        required: True
    global_timeout:
        description:
            - Overall expected timeout value for the CLI session in seconds.
        required: False
        default: 15
    login_delay:
        description:
            - Delay between session establishment and first expected response from the target
        required: False
        default: 5
    command_set:
        description:
            - List of commands to be executed in this session.
        required: True
        type: list
        suboptions:
            command:
                description:
                    - CLI command exactly as it would appear at a system prompt.
                    - To reduce dialogs, as many flags and parameters should be included as possible.
                required: True
            prompts:
                description:
                    - List of prompts and responses for the interactive parts of the command.
                required: False
                type: list
                suboptions:
                    question:
                        description:
                            - Prompt string as displayed by the CLI typically captured in a screen scrape.
                            - This string should be unambigouous and differentiated from other prompts.
                        required: True
                    response:
                        description:
                            - Answer to the prompt.  A default response is indicated by "".
                        required: True
            start_state:
                description:
                    - Assumed values for returned failure and changed state variables.
                    - These values are returned if no result tests change them.
                required: False
                type: list
                suboptions:
                    flag:
                        description:
                            - State variable to be set
                        choices: ['failed', 'changed']
                        required: True
                    value:
                        description:
                            - State variable default value
                        type: boolean
                        required: True
                default:
                    - flag: changed
                      value: False
                    - flag: failed
                      value: False
            result_tests:
                description:
                    - List of tests to be run to determine changes in the failed or changed state
                required: False
                type: list
                suboptions:
                    test:
                        description:
                            - Prompt string as displayed by the CLI typically captured in a screen scrape.
                            - This string should be unambigouous and differentiated from other prompts.
                        required: True
                    flag:
                        description:
                            - State variable to be set
                        choices: ['failed', 'changed']
                        required: True
                    value:
                        description:
                            - State variable default value
                        type: boolean
                        required: True
            exit_tests:
                description:
                    - List of strings other than the standard prompt that would indicated command termination.
                required: False
            timeout:
                description:
                    - Timeout value for this command if it should be different than the global value.
                    - Depending on the situation, a particular command may require more or less time.
                required: False
                default: -1 indicating the global value should be used.
'''

EXAMPLES = '''
  - name: run fos commands
    brocade_fos_command:
      switch_login: {{ username}}
      switch_password: {{ password }}
      switch_address: {{ switch_ip_address }}
      command_set:
        # 
        - command: timeout 30
          start_state:
            - flag: changed
              value: True

        - command: defzone --allaccess
          prompts:
            - question: Do you want to
              response: "yes"

        - command: cfgsave
          prompts:
            - question: Do you want to
              response: "yes"

        - command: dnsconfig --add -domain mydomain.com -serverip1 8.8.8.8 -serverip2 8.8.4.4

        - command: tstimezone America/Chicago

        - command: switchdisable

        - command: switchenable

        - command: 'portname -d "C.T.A.R"'

        - command: fabricprincipal --enable -p 0x03 -f

        - command: creditrecovmode --cfg onLrOnly

        - command: dlsset --enable -lossless

        - command: bannerset
          prompts:
            - question: Please input content of security banner
              response: "This is to demo the banner set command.\n."

        - command: ipfilter --clone ipv4_telnet_http -from default_ipv4
        - command: ipfilter --delrule ipv4_telnet_http -rule 2
        - command: ipfilter --addrule ipv4_telnet_http -rule 2 -sip any -dp 23 -proto tcp -act deny
        - command: ipfilter --activate ipv4_telnet_http 
        - command: ipfilter --show

        - command: snmpconfig --set systemgroup
          prompts:
            - question: sysDescr
              response: DemoSwitch
            - question: sysLocation
              response: San Jose
            - question: sysContact
              response: ""
            - question: authTrapEnabled
              response: "true"

        - command: auditcfg --class 1,2,3,4,5,8,9

        - command: syslogadmin --set -ip 10.155.2.151

'''

RETURN = '''
messages:
    description: Log of the terminal session.
    returned: always
    type: list
    sample: 
      - "SW170_X6-4:FID128:admin> timeout 30",
      - "IDLE Timeout Changed to 30 minutes",
      - "The modified IDLE Timeout will be in effect after NEXT login",
      - "SW170_X6-4:FID128:admin> defzone --allaccess",
      - "You are about to set the Default Zone access mode to All Access",
      - "Do you want to set the Default Zone access mode to All Access ? (yes, y, no, n): [no] yes",
      - "defzone setting is same and nothing to update.",
      - "",
      - "SW170_X6-4:FID128:admin>

'''



def open_shell(module, ip_address, username, password, hostkeymust, messages, globaltimeout):
    changed = False
    failed = False
    messages.append("")
    messages.append("SSH into " + ip_address)
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    if not hostkeymust:
        ssh.set_missing_host_key_policy(paramiko.client.WarningPolicy())
    try:
        ssh.connect(ip_address, username=username, password=password, timeout=globaltimeout)
    except paramiko.ssh_exception.AuthenticationException as exception:
        messages.append("invalid name/password")
        messages.append("Skipping due to error: " +  str(exception))
        failed = True
        module.fail_json(msg="Invalid login credentials.", messages=messages)
        #return ssh, shell, changed, failed
    except BaseException as exception:
        messages.append("Skipping due to error: " +  str(exception))
        failed = True
        module.fail_json(msg="Login error.", messages=messages)
        #return ssh, shell, changed, failed

    shell = ssh.invoke_shell()
    shell.settimeout(globaltimeout)

    return ssh, shell, changed, failed


def close_session(ssh_session):
    ssh_session.close()
    return

def send_characters(module, messages, shell, the_characters):

    try:
        shell.send(the_characters)
    except BaseException as exception:
        messages.append("Exiting due to send error: " +  str(exception))
        failed = True
        module.fail_json(msg="Send module failed", messages=messages, failed=failed)
    return


def get_prompt(module, messages, shell, login_delay):

    # Send a newline, wait for prompt, and flush everything up to this point (assuming motd, etc.)
    send_characters(module, messages, shell, "\n")
    time.sleep(login_delay)
    try:
        response = shell.recv(9999)
    except socket.timeout as exception:
        messages.append("Exiting due to error: " +  str(exception))
        failed = True
        module.fail_json(msg="Receive timeout.", failed=failed)

    # Send another newline to get a fresh prompt
    send_characters(module, messages, shell, "\n")

    # This will be the \n from the send.
    try:
        response = shell.recv(1)
    except socket.timeout as exception:
        messages.append("Exiting due to error: " +  str(exception))
        failed = True
        module.fail_json(msg="Receive timeout.", failed=failed)

    # This will be the \n from the prompt to begin on a new line.
    try:
        response = shell.recv(1)
    except socket.timeout as exception:
        messages.append("Exiting due to error: " +  str(exception))
        failed = True
        module.fail_json(msg="Receive timeout.")

    # This should be the prompt
    try:
        response = shell.recv(9999).decode()
    except socket.timeout as exception:
        messages.append("Exiting due to error: " +  str(exception))
        failed = True
        module.fail_json(msg="Receive timeout.")
    return str(response)

def receive_until_match(module, messages, shell, match_array, exit_array, prompt_change):
    response_buffer = ""
    index = -1

    found = False
    closed = False
    exited = False

    while not found and not closed and not exited:
        try:
            temp_buffer = shell.recv(9999).decode()
        except socket.timeout as exception:
            messages.append("Exiting due to error: " +  str(exception))

            failed = True
            messages.append(response_buffer.split("\r\n"))
            module.fail_json(msg="Receive timeout.", messages=messages, failed=failed)
        response_buffer += temp_buffer
        for i in range(len(match_array)):
            if match_array[i] in response_buffer:
                index = i
                found = True
                break
        if len(temp_buffer) == 0:
            closed = True
        for i in range(len(exit_array)):
            if exit_array[i] in response_buffer:
                exited = True
        if prompt_change:
            prompt_match = re.search("\n[a-zA-Z0-9_.-]*:?[a-zA-Z_0-9]*:[a-zA-Z_0-9_.-]*>", \
                response_buffer)
            if prompt_match is not None:
                new_prompt = prompt_match.group()[1:]
                exited = True
        else:
            new_prompt = None

    return index, response_buffer, exited, new_prompt

def cleanup_response(response_buffer):
    response_lines = response_buffer.split("\r\n")
    return response_lines


def main(argv):

    prompt_options = dict(
        question=dict(type='str', required=True),
        response=dict(type='str', required=True),
    )

    result_test_options = dict(
        test=dict(type='str', required=True),
        flag=dict(type='str', required=True, choices=['failed', 'changed']),
        value=dict(type='bool', required=True),

    )

    start_state_options = dict(
        flag=dict(type='str', required=True, choices=['failed', 'changed']),
        value=dict(type='bool', required=True),
    )

    command_set_options = dict(
        command=dict(type='str', required=True),
        prompts=dict(type='list', elements='dict', options=prompt_options, default=[]),
        start_state=dict(type='list', elements='dict', options=start_state_options,
                         default=[{"flag": "changed", "value": False},
                                  {"flag": "failed", "value": False}]),
        result_tests=dict(type='list', elements='dict', options=result_test_options, default=[]),
        exit_tests=dict(type='list', elements='str', default=[]),
        timeout=dict(type='int', default=-1),
    )


    argument_spec = dict(
        switch_login=dict(type='str'),
        switch_password=dict(type='str'),
        switch_address=dict(type='str'),
        global_timeout=dict(type='int', default=15),
        command_set=dict(type='list', elements='dict', options=command_set_options),
        hostkeymust=dict(type='bool', default=False),
        login_delay=dict(type='int', default=5),
    )
    #global messages

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)
    warnings = list()
    messages = list()

    changed = False
    failed = False

    prompt_change_commands = []
    prompt_change_commands.append("setcontext")

    # Wrangle out the variables
    switch_login = module.params['switch_login']
    switch_password = module.params['switch_password']
    switch_address = module.params['switch_address']
    command_set = module.params['command_set']
    hostkeymust = module.params['hostkeymust']
    global_timeout = module.params['global_timeout']
    login_delay = module.params['login_delay']

    result = {}

    # Establish session with switch
    ssh, shell, changed, failed = open_shell(module, switch_address, switch_login, switch_password,
                                             hostkeymust, messages, global_timeout)

    # Discover prompt string
    switch_prompt = get_prompt(module, messages, shell, login_delay)
    collected_responses = switch_prompt


    command_state = {'changed': False, 'failed': False}

    # For each command
    for command_index in range(len(command_set)):
        # Build the expected responses for each question or prompt
        questions = []

        # Set the individual command starting state

        for i in range(len(command_set[command_index]['start_state'])):
            command_state[command_set[command_index]['start_state'][i]['flag']] = \
                command_set[command_index]['start_state'][i]['value']

        if len(command_set[command_index]['prompts']) > 0:
            for prompt_index in range(len(command_set[command_index]['prompts'])):
                questions.append(command_set[command_index]['prompts'][prompt_index]['question'])

        # Build the list of possible exit strings in addition to the prompt
        exit_array = list(command_set[command_index]['exit_tests'])
        exit_array.append(switch_prompt)

        # Start the accumulated dialog with the command
        command_results = ""

        # Set the command specific timeout if one is indicated
        if command_set[command_index]['timeout'] == -1:
            shell.settimeout(global_timeout)
        else:
            shell.settimeout(command_set[command_index]['timeout'])

        # If the command is in the prompt change list, set the flag.  Otherwise clear the flag
        prompt_change = False
        for i in range(len(prompt_change_commands)):
            if prompt_change_commands[i] in command_set[command_index]['command']:
                prompt_change = True

        # Send the inital command line
        send_characters(module, messages, shell, command_set[command_index]['command'] + "\n")

        # This loop will repeat until either the prompt or another exit string is found
        back_to_prompt = False
        while not back_to_prompt:
            prompt_index, response_buffer, exited, new_prompt = \
                receive_until_match(module, messages, shell, questions, exit_array, prompt_change)
            command_results += response_buffer
            if exited:
                back_to_prompt = True
                if prompt_change:
                    switch_prompt = new_prompt
            else:
                send_characters(module, messages, shell,
                                command_set[command_index]['prompts'][prompt_index]['response'] + "\n")


        for check_index in range(len(command_set[command_index]['result_tests'])):
            if command_set[command_index]['result_tests'][check_index]['test'] in command_results:
                command_state[command_set[command_index]['result_tests'][check_index]['flag']] = \
                    command_set[command_index]['result_tests'][check_index]['value']

        if command_state['changed'] is True:
            changed = True
        if command_state['failed'] is True:
            failed = True
        collected_responses += command_results

        # Look at final fail and changed state and update accordingly

    # End session and return
    #messages.append(cleanup_response(collected_responses))
    messages = cleanup_response(collected_responses)


    close_session(ssh)


    #result['stdout'] = show_stdout
    #result['stderr'] = show_stderr
    result['changed'] = changed
    result['failed'] = failed
    result['messages'] = messages
    result['warnings'] = warnings
    #result['switch_prompt'] = switch_prompt

    # Debugging returns
    #result['command_set'] = command_set
    module.exit_json(**result)

if __name__ == "__main__":
    main(sys.argv[1:])
