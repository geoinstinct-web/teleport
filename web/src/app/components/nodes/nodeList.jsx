/*
Copyright 2015 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import React from 'react';
import { Link } from  'react-router';
import { sortBy } from 'lodash';
import { isMatch } from 'app/lib/objectUtils';
import InputSearch from './../inputSearch';
import { Table, Column, Cell, SortHeaderCell, SortTypes, EmptyIndicator } from 'app/components/table.jsx';
import ClusterSelector from './../clusterSelector.jsx';
import cfg from 'app/config';

const EmptyValue = ({ text='Empty' }) => (    
  <small className="text-muted">
    <span>{text}</span>
  </small>
);
    
const TextCell = ({rowIndex, data, columnKey, ...props}) => (
  <Cell {...props}>
    {data[rowIndex][columnKey]}
  </Cell>
);

const TagCell = ({rowIndex, data, ...props}) => {
  let { tags } = data[rowIndex];    
  let $content = tags.map((item, index) => (
    <span key={index} title={`${item.role}:${item.value}`} className="label label-default grv-nodes-table-label">
      {item.role} <li className="fa fa-long-arrow-right m-r-xs"/> 
      {item.value}
    </span>
  ));

  if ($content.length === 0) {
    $content = <EmptyValue text="No assigned labels"/>
  }
  
  return (
    <Cell {...props}>
      {$content}
    </Cell>
  )  
}

const LoginCell = ({logins, rowIndex, data, ...props}) => {
  if(!logins ||logins.length === 0){
    return <Cell {...props} />;
  }

  let { id, siteId } = data[rowIndex];
  let $lis = [];
    
  for (var i = 0; i < logins.length; i++){
    let termUrl = cfg.getTerminalLoginUrl({
      siteId: siteId,
      serverId: id,
      login: logins[i]
    })
      
    $lis.push(
      <li key={i}>        
        <Link to={termUrl}>
          {logins[i]}
        </Link>
      </li>        
    );
  } 

  let defaultTermUrl = cfg.getTerminalLoginUrl({
    siteId: siteId,
    serverId: id,
    login: logins[0]
  })

  return (
    <Cell {...props}>
      <div style={{display: "flex"}}>
        <div style={{display: "flex"}} className="btn-group">        
          <Link className="btn btn-xs btn-primary" to={defaultTermUrl}>
            {logins[0]}
          </Link>
          {
            $lis.length > 1 ? (
              [
                <button key={0} data-toggle="dropdown" className="btn btn-default btn-xs dropdown-toggle" aria-expanded="true">
                  <span className="caret"></span>
                </button>,
                <ul key={1} className="dropdown-menu pull-right">
                  {$lis}
                </ul>
              ] )
            : null
          }
        </div>
      </div>  
    </Cell>
  )
};

class NodeList extends React.Component {

  searchableProps = ['addr', 'hostname', 'tags'];

  constructor(props) {
    super(props);
    this.state = {        
        filter: '',
        colSortDirs: { hostname: SortTypes.DESC }
    };
  }
  
  onSortChange = (columnKey, sortDir) => {
    this.state.colSortDirs = { [columnKey]: sortDir };
    this.setState(this.state);
  }

  onFilterChange = value => {
    this.state.filter = value;
    this.setState(this.state);
  }
  
  searchAndFilterCb(targetValue, searchValue, propName){
    if(propName === 'tags'){
      return targetValue.some((item) => {
        let {role, value} = item;
        return role.toLocaleUpperCase().indexOf(searchValue) !==-1 ||
          value.toLocaleUpperCase().indexOf(searchValue) !==-1;
      });
    }
  }

  sortAndFilter(data) {
    let { colSortDirs } = this.state;    
    let filtered = data      
      .filter(obj => isMatch(obj, this.state.filter, {
        searchableProps: this.searchableProps,
        cb: this.searchAndFilterCb
      }));
        
    let columnKey = Object.getOwnPropertyNames(colSortDirs)[0];
    let sortDir = colSortDirs[columnKey];
    let sorted = sortBy(filtered, columnKey);
    if(sortDir === SortTypes.ASC){
      sorted = sorted.reverse();
    }

    return sorted;
  }

  render() {      
    let { nodeRecords, logins, onLoginClick } = this.props;       
    let data = this.sortAndFilter(nodeRecords);                                     
    return (
      <div className="grv-nodes m-t">                
        <div className="grv-flex grv-header" style={{ justifyContent: "space-between" }}>                    
          <h2 className="text-center no-margins"> Nodes </h2>          
          <div className="grv-flex">
            <ClusterSelector/>  
            <InputSearch onChange={this.onFilterChange} />                        
          </div>
        </div>
        <div className="m-t">
          {
            data.length === 0 && this.state.filter.length > 0 ? <EmptyIndicator text="No matching nodes found"/> :

            <Table rowCount={data.length} className="table-striped grv-nodes-table">
              <Column
                columnKey="hostname"
                header={
                  <SortHeaderCell
                    sortDir={this.state.colSortDirs.hostname}
                    onSortChange={this.onSortChange}
                    title="Hostname"
                  />
                }
                cell={<TextCell data={data}/> }
              />
              <Column
                columnKey="addr"
                header={
                  <SortHeaderCell
                    sortDir={this.state.colSortDirs.addr}
                    onSortChange={this.onSortChange}
                    title="Address"
                  />
                }
                cell={<TextCell data={data}/> }
              />
              <Column
                columnKey="tags"
                header={<Cell>Labels</Cell> }
                cell={<TagCell data={data}/> }
              />
              <Column
                columnKey="roles"
                onLoginClick={onLoginClick}
                header={<Cell>Login as</Cell> }
                cell={<LoginCell data={data} logins={logins}/> }
              />
            </Table>
          }
        </div>
      </div>
    )
  }
}

export default NodeList;
