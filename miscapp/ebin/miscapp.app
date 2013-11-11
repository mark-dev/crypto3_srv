{application, miscapp,
 [
  {description, "miscapp"},
  {vsn, "0.1.0"},
  {id, "miscapp"},
  {modules,      [erl_make_certs,
		  erl_make_certs_wrap,
		  ets_mgr,
		  tests,
		  sslv2decoder,
		  sslv2encoder
		 ]},
  {registered,   []},
  {applications, [kernel, stdlib]},
  {env, []}
 ]
}.
