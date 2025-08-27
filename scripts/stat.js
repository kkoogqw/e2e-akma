
let res = "{\"nw_reg_af_req_time\":33437033,\"nw_reg_hn_req_time\":21422375,\"nw_reg_hn_com_time\":39855225,\"nw_reg_hn_fin_time\":85684241,\"nw_reg_af_fin_time\":14764283,\"cp_reg_hn_com_time\":211220725,\"cp_reg_sign_time\":859431491,\"cp_reg_hn_fin_time\":82712716,\"nw_login_af_req_time\":1355441,\"nw_login_hn_req_time\":13406433,\"nw_login_hn_fin_time\":77371500,\"nw_login_af_fin_time\":7841758,\"cp_login_hn_com_time\":96650833,\"cp_login_sign_time\":516930283,\"cp_login_hn_fin_time\":77177366,\"reg_computation_time\":1153364933,\"reg_network_time\":195163159,\"login_computation_time\":3453792417,\"login_network_time\":499875667}"

let stat = JSON.parse(res);
console.log(stat);