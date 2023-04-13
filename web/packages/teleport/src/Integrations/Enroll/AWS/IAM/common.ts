import styled from 'styled-components';

import { Stage } from '../stages';

export interface CommonIAMProps {
  stage: Stage;
}

export const Header = styled.div`
  font-size: 22px;
  margin-bottom: 20px;
  display: flex;
`;

export const Footer = styled.div`
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  height: 46px;
  border-top: 1px solid #dcdcdc;
  display: flex;
  justify-content: flex-end;
  align-items: center;
  padding-right: 30px;
`;

export const Page = styled.div`
  display: flex;
  flex: 1;
`;

export const Sidebar = styled.div`
  display: flex;
  flex-direction: column;
  border-right: 1px solid rgba(0, 0, 0, 0.1);
  flex: 0 0 250px;
  width: 250px;
  height: inherit;
`;

export const SidebarSectionTitle = styled.div`
  font-weight: 700;
  color: rgba(0, 0, 0, 0.5);
  padding: 0 20px;
  margin-top: 15px;
  margin-bottom: 5px;
`;

export const SidebarTitle = styled.div`
  font-size: 18px;
  padding: 20px 20px;
  font-weight: bold;
  border-bottom: 1px solid rgba(0, 0, 0, 0.07);
  margin-bottom: 20px;
`;

export const SidebarLink = styled.div`
  padding: 0 20px;
  margin-bottom: 5px;
  position: relative;
  z-index: 2;
`;

export const SidebarLinkActive = styled(SidebarLink)`
  color: #0073bb;
  font-weight: 500;
`;

export const Content = styled.div`
  padding: 30px;
  box-sizing: border-box;
  flex: 0 0 630px;
  width: 630px;
`;

export const Title = styled.div`
  font-size: 18px;
  margin-bottom: 30px;
`;

export const Blur = styled.div`
  filter: blur(5px);
  width: 100%;
`;

export const Breadcrumb = styled.div`
  display: flex;
`;

export const BreadcrumbItem = styled.div`
  color: #0073bb;
`;

export const BreadcrumbItemActive = styled(BreadcrumbItem)`
  font-weight: 700;
  color: #687078;
`;

export const BreadcrumbIconContainer = styled.div`
  margin: 0 10px;
`;

export const NextButton = styled.div`
  background: linear-gradient(#2c8bea, #1267bc);
  color: white;
  padding: 5px 15px;
  font-size: 14px;
  font-weight: 700;
  border-radius: 4px;
  border: 1px solid #1d67b3;
`;

export const RoleButton = styled.div`
  background: linear-gradient(#fff, #dedede);
  color: #444;
  padding: 5px 10px;
  font-weight: 700;
  border-radius: 4px;
  border: 1px solid #b8b8b8;
`;

export const Section = styled.div`
  display: flex;
  align-items: center;
  margin-bottom: 20px;
`;

export const SectionTitle = styled.div`
  font-weight: bold;
  width: 100px;
  text-align: right;
  padding-right: 15px;
`;

export const SectionContent = styled.div`
  display: flex;
  align-items: center;
  width: 300px;
  position: relative;
`;

export const SectionDropdown = styled.div`
  position: relative;
  width: 300px;
`;

export const SectionDropdownSelected = styled.div`
  border: 1px solid #ccc;
  padding: 5px 10px;
  border-radius: 4px;
`;

export const SubHeader = styled.div`
  font-size: 20px;
  margin-bottom: 15px;
  display: flex;
  border-bottom: 1px solid #ccc;
  padding-bottom: 5px;
`;

export const TableTitle = styled.div`
  background: #e3e3e3;
  border: 1px solid #cccccc;
  padding: 13px 10px;
`;

export const TableSearch = styled.div`
  background: white;
  border: 1px solid #cccccc;
  border-radius: 3px;
  width: 200px;
  padding: 3px 10px;
`;

export const TableHeader = styled.div`
  background-image: linear-gradient(#eee, #e0e0e0);
  padding: 10px 45px;
  font-weight: bold;
  border: 1px solid #ccc;
  border-top: none;
`;

export const TableCheckBox = styled.div`
  width: 10px;
  height: 10px;
  margin-right: 20px;
  border-radius: 3px;
`;

export const TableItem = styled.div<{ selected?: boolean }>`
  display: flex;
  align-items: center;
  padding: 10px 15px;
  border-bottom: 1px solid #cccccc;
  background: ${p => (p.selected ? '#e6f3ff' : 'white')};

  ${TableCheckBox} {
    background: ${p => (p.selected ? '#1066bb' : 'white')};
    border: 1px solid ${p => (p.selected ? '#1066bb' : '#ccc')};
  }
`;
