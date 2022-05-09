dashboard_top = """
    <div class='row'>
        <div class='col-lg-3 col-md-6'>
            <div class='panel panel-primary'>
                <div class='panel-heading'>
                    <div class='row'>
                        <div class='col-xs-3'>
                            <i class='fa  fa-gears fa-5x'></i>
                        </div>
                        <div class='col-xs-9 text-right'>
                            <div class='huge'>{0}</div>
                            <div>在线主机</div>
                        </div>
                    </div>
                </div>
                <a href='{1}'>
                    <div class='panel-footer'>
                        <span class='pull-left'>View Details</span>
                        <span class='pull-right'><i class='fa fa-arrow-circle-right'></i></span>
                        <div class='clearfix'></div>
                    </div>
                </a>
            </div>
        </div>
        <div class='col-lg-3 col-md-6'>
            <div class='panel panel-green'>
                <div class='panel-heading'>
                    <div class='row'>
                        <div class='col-xs-3'>
                            <i class='fa fa-support fa-5x'></i>
                        </div>
                        <div class='col-xs-9 text-right'>
                            <div class='huge'>{2}</div>
                            <div>开放端口</div>
                        </div>
                    </div>
                </div>
                <a href='{3}'>
                    <div class='panel-footer'>
                        <span class='pull-left'>View Details</span>
                        <span class='pull-right'><i class='fa fa-arrow-circle-right'></i></span>
                        <div class='clearfix'></div>
                    </div>
                </a>
            </div>
        </div>
        <div class='col-lg-3 col-md-6'>
            <div class='panel panel-yellow'>
                <div class='panel-heading'>
                    <div class='row'>
                        <div class='col-xs-3'>
                            <i class='fa fa-exchange fa-5x'></i>
                        </div>
                        <div class='col-xs-9 text-right'>
                            <div class='huge'>{4}</div>
                            <div>发现服务</div>
                        </div>
                    </div>
                </div>
                <a href='{5}'>
                    <div class='panel-footer'>
                        <span class='pull-left'>View Details</span>
                        <span class='pull-right'><i class='fa fa-arrow-circle-right'></i></span>
                        <div class='clearfix'></div>
                    </div>
                </a>
            </div>
        </div>
        <div class='col-lg-3 col-md-6'>
            <div class='panel panel-red'>
                <div class='panel-heading'>
                    <div class='row'>
                        <div class='col-xs-3'>
                            <i class='fa fa-support fa-5x'></i>
                        </div>
                        <div class='col-xs-9 text-right'>
                            <div class='huge'>{6}</div>
                            <div>终端资产</div>
                        </div>
                    </div>
                </div>
                <a href='{7}'>
                    <div class='panel-footer'>
                        <span class='pull-left'>View Details</span>
                        <span class='pull-right'><i class='fa fa-arrow-circle-right'></i></span>
                        <div class='clearfix'></div>
                    </div>
                </a>
            </div>
        </div>
    </div>
"""


"""

            <h4>扫描任务信息</h4>
            <p><Strong>执行时间:</Strong>&nbsp; &nbsp;{0}</p>
            <p><Strong>任务类型:</Strong>&nbsp;&nbsp; {1}</p>
            <p><Strong>扫描用时:</Strong>&nbsp;&nbsp;{2} (seconds)</p>
            <p><Strong>地址数量:</Strong>&nbsp;&nbsp;{3} </p>
            
"""
dashboard_scaninfo = """
<a href="#" class="list-group-item">
                                        <i class="fa fa-comment fa-fw"></i> 执行时间:{0}
                                       
                                        </span>
                                    </a>
                                    <a href="#" class="list-group-item">
                                        <i class="fa fa-comment fa-fw"></i> 任务类型:{1}
                                       
                                        </span>
                                    </a>
                                    <a href="#" class="list-group-item">
                                        <i class="fa fa-comment fa-fw"></i> 扫描用时:{2} &nbsp;&nbsp;（s）
                                       
                                        </span>
                                    </a>
                                    <a href="#" class="list-group-item">
                                        <i class="fa fa-comment fa-fw"></i> 扫描地址数量:{3}
                                       
                                        </span>
                                    </a>
                                    """