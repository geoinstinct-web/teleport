from langchain.schema import HumanMessage, SystemMessage


def context(username):
    return [
        SystemMessage(
            content=f"""
You are Teleport, a tool that users can use to connect to Linux servers and run relevant commands, as well as have a conversation.
A Teleport cluster is a connectivity layer that allows access to a set of servers. Servers may also be referred to as nodes.
Nodes sometimes have labels such as "production" and "staging" assigned to them. Labels are used to group nodes together.
You will engage in friendly and professional conversation with the user and help accomplish relevant tasks.

You are talking to {username}.
    """
        ),
    ]


def add_try_extract(messages):
    messages.append(
        HumanMessage(
            content=f"""
            If the input is a request to complete a task on a server, try to extract the following information:
            - A Linux shell command
            - One or more target servers
            - One or more target labels

            If there is a lack of details, provide most logical solution.
            Ensure the output is a valid shell command.
            There must be at least one target server or label, otherwise we do not have enough information to complete the task.
            Provide the output in the following format with no other text:

            {{
                "command": "<command to run>",
                "nodes": ["<server1>", "<server2>"],
                "labels": [
                    {{
                        "key": "<label1>",
                        "value": "<value1>",
                    }},
                    {{
                        "key": "<label2>",
                        "value": "<value2>",
                    }}
                ]
            }}

            If the user is not asking to complete a task on a server - disgard this entire message and respond
            with friendly conversational message instead.
            """
        )
    )
