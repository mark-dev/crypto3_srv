{application, tcp_server,
 [
  {description, "Demo TCP server"},
  {vsn, "0.1.0"},
  {id, "tcp_server"},
  {modules,      [tcp_manager, tcp_chat_fsm, tcp_server_app]},
  {registered,   [tcp_server_sup, tcp_manager]},
  {applications, [kernel, stdlib]},
  %%
  %% mod: Specify the module name to start the application, plus args
  %%
  {mod, {tcp_server_app, []}},
  {env, []}
 ]
}.
